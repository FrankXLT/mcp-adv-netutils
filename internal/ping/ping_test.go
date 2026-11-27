package ping

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func startLoopbackTCPListener(t *testing.T) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	return port, func() {
		_ = ln.Close()
		wg.Wait()
	}
}

func reserveClosedLoopbackPort(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	require.NoError(t, ln.Close())
	return port
}

func marshalICMPMessage(t *testing.T, msgType icmp.Type, body icmp.MessageBody) []byte {
	t.Helper()

	raw, err := (&icmp.Message{Type: msgType, Code: 0, Body: body}).Marshal(nil)
	require.NoError(t, err)
	return raw
}

func TestPerformSimplePingPorts_TCPFallback(t *testing.T) {
	t.Parallel()

	t.Run("connects to loopback TCP listener and computes clean stats", func(t *testing.T) {
		t.Parallel()

		openPort, cleanup := startLoopbackTCPListener(t)
		defer cleanup()

		resp, err := performSimplePingPorts(context.Background(), "127.0.0.1", net.ParseIP("127.0.0.1"), 2, 2*time.Second, []string{openPort})
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, "127.0.0.1", resp.Target)
		assert.Equal(t, "127.0.0.1", resp.ResolvedIP)
		assert.Equal(t, probeModeTCPFallback, resp.ProbeMode)
		assert.Equal(t, 2, resp.PacketsSent)
		assert.Equal(t, 2, resp.PacketsReceived)
		assert.InDelta(t, 0.0, resp.PacketLoss, 0.001)
		require.Len(t, resp.Results, 2)

		for idx, res := range resp.Results {
			assert.Equal(t, idx+1, res.Sequence)
			assert.True(t, res.Success)
			assert.Empty(t, res.Error)
			assert.GreaterOrEqual(t, res.ResponseTime, 0.0)
		}

		assert.GreaterOrEqual(t, resp.MinRTT, 0.0)
		assert.GreaterOrEqual(t, resp.MaxRTT, resp.MinRTT)
		assert.GreaterOrEqual(t, resp.AvgRTT, resp.MinRTT)
		assert.LessOrEqual(t, resp.AvgRTT, resp.MaxRTT)
		assert.NotEmpty(t, resp.Timestamp)

		encoded, err := json.Marshal(resp)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"probe_mode":"tcp_fallback"`)
	})

	t.Run("falls through closed port to open loopback listener", func(t *testing.T) {
		t.Parallel()

		closedPort := reserveClosedLoopbackPort(t)
		openPort, cleanup := startLoopbackTCPListener(t)
		defer cleanup()

		resp, err := performSimplePingPorts(context.Background(), "127.0.0.1", net.ParseIP("127.0.0.1"), 1, 2*time.Second, []string{closedPort, openPort})
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, probeModeTCPFallback, resp.ProbeMode)
		assert.Equal(t, 1, resp.PacketsSent)
		assert.Equal(t, 1, resp.PacketsReceived)
		assert.InDelta(t, 0.0, resp.PacketLoss, 0.001)
		require.Len(t, resp.Results, 1)
		assert.True(t, resp.Results[0].Success)
	})

	t.Run("reports 100 percent loss when all ports fail", func(t *testing.T) {
		t.Parallel()

		closedPort := reserveClosedLoopbackPort(t)

		resp, err := performSimplePingPorts(context.Background(), "127.0.0.1", net.ParseIP("127.0.0.1"), 1, time.Second, []string{closedPort})
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, probeModeTCPFallback, resp.ProbeMode)
		assert.Equal(t, 1, resp.PacketsSent)
		assert.Equal(t, 0, resp.PacketsReceived)
		assert.InDelta(t, 100.0, resp.PacketLoss, 0.001)
		require.Len(t, resp.Results, 1)
		assert.False(t, resp.Results[0].Success)
		assert.Contains(t, resp.Results[0].Error, "connection failed to all tested ports")
	})
}

func TestMatchICMPEchoReply(t *testing.T) {
	t.Parallel()

	v4Proto := ipv4.ICMPTypeEchoReply.Protocol()
	v6Proto := ipv6.ICMPTypeEchoReply.Protocol()
	const expectedID, expectedSeq = 4242, 7

	tests := []struct {
		name   string
		proto  int
		packet []byte
		want   bool
	}{
		{
			name:   "IPv4 matching echo reply",
			proto:  v4Proto,
			packet: marshalICMPMessage(t, ipv4.ICMPTypeEchoReply, &icmp.Echo{ID: expectedID, Seq: expectedSeq, Data: []byte("pong")}),
			want:   true,
		},
		{
			name:   "IPv4 mismatched echo ID",
			proto:  v4Proto,
			packet: marshalICMPMessage(t, ipv4.ICMPTypeEchoReply, &icmp.Echo{ID: expectedID + 1, Seq: expectedSeq, Data: []byte("pong")}),
			want:   false,
		},
		{
			name:   "IPv4 mismatched echo sequence",
			proto:  v4Proto,
			packet: marshalICMPMessage(t, ipv4.ICMPTypeEchoReply, &icmp.Echo{ID: expectedID, Seq: expectedSeq + 1, Data: []byte("pong")}),
			want:   false,
		},
		{
			name:   "IPv4 echo request ignored even with matching ID and seq",
			proto:  v4Proto,
			packet: marshalICMPMessage(t, ipv4.ICMPTypeEcho, &icmp.Echo{ID: expectedID, Seq: expectedSeq, Data: []byte("ping")}),
			want:   false,
		},
		{
			name:   "IPv4 destination unreachable ignored",
			proto:  v4Proto,
			packet: marshalICMPMessage(t, ipv4.ICMPTypeDestinationUnreachable, &icmp.DstUnreach{Data: make([]byte, 28)}),
			want:   false,
		},
		{
			name:   "IPv6 matching echo reply",
			proto:  v6Proto,
			packet: marshalICMPMessage(t, ipv6.ICMPTypeEchoReply, &icmp.Echo{ID: expectedID, Seq: expectedSeq, Data: []byte("pong6")}),
			want:   true,
		},
		{
			name:   "IPv6 mismatched echo ID",
			proto:  v6Proto,
			packet: marshalICMPMessage(t, ipv6.ICMPTypeEchoReply, &icmp.Echo{ID: 999, Seq: expectedSeq, Data: []byte("pong6")}),
			want:   false,
		},
		{
			name:   "IPv6 echo request ignored even with matching ID and seq",
			proto:  v6Proto,
			packet: marshalICMPMessage(t, ipv6.ICMPTypeEchoRequest, &icmp.Echo{ID: expectedID, Seq: expectedSeq, Data: []byte("ping6")}),
			want:   false,
		},
		{name: "truncated malformed packet ignored", proto: v4Proto, packet: []byte{0x00, 0x01}, want: false},
		{name: "empty packet ignored", proto: v4Proto, packet: nil, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, matchICMPEchoReply(tc.proto, tc.packet, expectedID, expectedSeq))
		})
	}
}

func TestNextEchoID(t *testing.T) {
	t.Parallel()

	const workers, perWorker = 8, 64
	ids := make(chan uint16, workers*perWorker)

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perWorker {
				ids <- nextEchoID()
			}
		}()
	}
	wg.Wait()
	close(ids)

	seen := make(map[uint16]struct{}, workers*perWorker)
	for id := range ids {
		seen[id] = struct{}{}
	}
	assert.Len(t, seen, workers*perWorker)
}

func TestExecute_TargetGuard(t *testing.T) {
	t.Parallel()

	t.Run("blocks cloud metadata IP 169.254.169.254", func(t *testing.T) {
		t.Parallel()

		guard, err := security.NewTargetGuard(nil, nil)
		require.NoError(t, err)

		count := 1
		resp, err := Execute(context.Background(), PingParams{Target: "169.254.169.254", Count: &count}, &Config{Timeout: time.Second, Count: 1, Guard: guard})
		require.Error(t, err)
		require.ErrorIs(t, err, security.ErrTargetDenied)
		assert.Nil(t, resp)
	})

	t.Run("HandlePing enforces TargetGuard on 169.254.169.254", func(t *testing.T) {
		t.Parallel()

		guard, err := security.NewTargetGuard(nil, nil)
		require.NoError(t, err)

		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]interface{}{"target": "169.254.169.254", "count": 1},
			},
		}

		res, err := HandlePing(context.Background(), request, &Config{Timeout: time.Second, Count: 1, Guard: guard})
		require.Error(t, err)
		require.ErrorIs(t, err, security.ErrTargetDenied)
		assert.Nil(t, res)
	})

	t.Run("blocks private IP when blockPrivate is enabled", func(t *testing.T) {
		t.Parallel()

		guard, err := security.NewTargetGuardWithOptions(nil, nil, true)
		require.NoError(t, err)

		resp, err := Execute(context.Background(), PingParams{Target: "127.0.0.1"}, &Config{Timeout: time.Second, Count: 1, Guard: guard})
		require.Error(t, err)
		require.ErrorIs(t, err, security.ErrTargetDenied)
		assert.Nil(t, resp)
	})

	t.Run("enforces allow CIDR policy and rejects flag-like target", func(t *testing.T) {
		t.Parallel()

		guard, err := security.NewTargetGuard([]string{"192.0.2.0/24"}, nil)
		require.NoError(t, err)

		_, err = Execute(context.Background(), PingParams{Target: "198.51.100.1"}, &Config{Timeout: time.Second, Count: 1, Guard: guard})
		require.ErrorIs(t, err, security.ErrTargetNotAllowed)

		_, err = Execute(context.Background(), PingParams{Target: "-c1"}, &Config{Timeout: time.Second, Count: 1, Guard: guard})
		require.ErrorIs(t, err, security.ErrTargetInvalid)
	})
}

func TestExecute_ContextCancellation(t *testing.T) {
	t.Parallel()

	t.Run("pre-canceled context aborts Execute immediately", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		count := 2
		resp, err := Execute(ctx, PingParams{Target: "127.0.0.1", Count: &count}, &Config{Timeout: 5 * time.Second, Count: 2})
		require.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, resp)
	})

	t.Run("pre-expired deadline aborts Execute immediately", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()

		resp, err := Execute(ctx, PingParams{Target: "127.0.0.1"}, &Config{Timeout: 5 * time.Second, Count: 1})
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, resp)
	})

	t.Run("mid-flight cancellation interrupts waitBetweenPings quickly", func(t *testing.T) {
		t.Parallel()

		openPort, cleanup := startLoopbackTCPListener(t)
		defer cleanup()

		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(50*time.Millisecond, cancel)

		start := time.Now()
		resp, err := performSimplePingPorts(ctx, "127.0.0.1", net.ParseIP("127.0.0.1"), 4, 5*time.Second, []string{openPort})
		elapsed := time.Since(start)

		require.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, resp)
		assert.Less(t, elapsed, 500*time.Millisecond)
	})

	t.Run("waitBetweenPings exits immediately on cancel and skips last wait", func(t *testing.T) {
		t.Parallel()

		assert.True(t, waitBetweenPings(context.Background(), 2, 3))

		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(25*time.Millisecond, cancel)
		start := time.Now()
		assert.False(t, waitBetweenPings(ctx, 0, 3))
		assert.Less(t, time.Since(start), 300*time.Millisecond)
	})

	t.Run("effectiveDeadline clamps to earlier context deadline", func(t *testing.T) {
		t.Parallel()

		ctxDeadline := time.Now().Add(150 * time.Millisecond)
		ctx, cancel := context.WithDeadline(context.Background(), ctxDeadline)
		defer cancel()

		got := effectiveDeadline(ctx, 5*time.Second)
		assert.True(t, got.Equal(ctxDeadline) || got.Before(ctxDeadline.Add(time.Millisecond)))

		gotNoCtx := effectiveDeadline(context.Background(), 200*time.Millisecond)
		assert.WithinDuration(t, time.Now().Add(200*time.Millisecond), gotNoCtx, 50*time.Millisecond)
	})
}

func TestExecute_ValidationAndHandlePing(t *testing.T) {
	t.Parallel()

	t.Run("nil context rejected", func(t *testing.T) {
		t.Parallel()

		//nolint:staticcheck // intentionally testing nil context guard
		resp, err := Execute(nil, PingParams{Target: "127.0.0.1"}, nil)
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "context must not be nil")
	})

	t.Run("empty target rejected", func(t *testing.T) {
		t.Parallel()

		resp, err := Execute(context.Background(), PingParams{Target: "   "}, nil)
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), `parameter "target" is required`)
	})

	t.Run("HandlePing rejects malformed argument types", func(t *testing.T) {
		t.Parallel()

		request := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]interface{}{"target": 12345},
			},
		}

		res, err := HandlePing(context.Background(), request, &Config{Timeout: time.Second, Count: 1})
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "failed to parse tool input")
	})

	t.Run("error sentinel sanity check", func(t *testing.T) {
		t.Parallel()

		assert.NotErrorIs(t, errors.New("other"), security.ErrTargetDenied)
	})
}
