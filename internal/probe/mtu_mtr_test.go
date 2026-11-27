package probe

import (
	"context"
	"encoding/binary"
	"math"
	"net"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestTargetGuardBlocksMetadataAndInvalidInputs(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	defaultGuard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)

	strictGuard, err := security.NewTargetGuardWithOptions(nil, nil, true)
	require.NoError(t, err)

	blockedCases := []struct {
		name    string
		target  string
		guard   *security.TargetGuard
		wantErr error
	}{
		{
			name:    "nil guard blocks IPv4 cloud metadata",
			target:  "169.254.169.254",
			guard:   nil,
			wantErr: security.ErrTargetDenied,
		},
		{
			name:    "default guard blocks IPv4 cloud metadata",
			target:  "169.254.169.254",
			guard:   defaultGuard,
			wantErr: security.ErrTargetDenied,
		},
		{
			name:    "default guard blocks IPv6 cloud metadata",
			target:  "fd00:ec2::254",
			guard:   defaultGuard,
			wantErr: security.ErrTargetDenied,
		},
		{
			name:    "strict guard blocks loopback private IP",
			target:  "127.0.0.1",
			guard:   strictGuard,
			wantErr: security.ErrTargetDenied,
		},
		{
			name:    "leading dash rejected",
			target:  "-n",
			guard:   defaultGuard,
			wantErr: security.ErrTargetInvalid,
		},
		{
			name:    "empty target rejected",
			target:  "   ",
			guard:   nil,
			wantErr: security.ErrTargetInvalid,
		},
	}

	for _, tc := range blockedCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, mtuErr := ExecuteMTUProbe(ctx, MTUProbeParams{Target: tc.target}, tc.guard)
			require.Error(t, mtuErr)
			require.ErrorIs(t, mtuErr, tc.wantErr)

			_, mtrErr := ExecuteMTRQuality(ctx, MTRParams{Target: tc.target}, tc.guard)
			require.Error(t, mtrErr)
			require.ErrorIs(t, mtrErr, tc.wantErr)
		})
	}

	t.Run("invalid protocol rejected", func(t *testing.T) {
		t.Parallel()
		_, protoErr := ExecuteMTUProbe(ctx, MTUProbeParams{Target: "127.0.0.1", Protocol: "sctp"}, defaultGuard)
		require.Error(t, protoErr)
		require.ErrorIs(t, protoErr, errInvalidMTUProtocol)
	})

	t.Run("nil context rejected", func(t *testing.T) {
		t.Parallel()
		//nolint:staticcheck // Intentionally verifying nil context defense.
		_, mtuErr := ExecuteMTUProbe(nil, MTUProbeParams{Target: "127.0.0.1"}, defaultGuard)
		require.Error(t, mtuErr)
		//nolint:staticcheck // Intentionally verifying nil context defense.
		_, mtrErr := ExecuteMTRQuality(nil, MTRParams{Target: "127.0.0.1"}, defaultGuard)
		require.Error(t, mtrErr)
	})
}

func TestMTUParamNormalizationAndQuickCandidates(t *testing.T) {
	t.Parallel()

	minMTU, maxMTU, proto, err := normalizeMTUParams(MTUProbeParams{})
	require.NoError(t, err)
	assert.Equal(t, 576, minMTU)
	assert.Equal(t, 1500, maxMTU)
	assert.Equal(t, "udp", proto)

	assert.Equal(t, []int{1500, 1492, 1420, 1280, 576}, buildQuickMTUCandidates(576, 1500))
	assert.Equal(t, []int{1450, 1420, 1280, 1200}, buildQuickMTUCandidates(1200, 1450))
	assert.Equal(t, []int{1400}, buildQuickMTUCandidates(1400, 1400))

	_, _, _, rangeErr := normalizeMTUParams(MTUProbeParams{MinMTU: 1500, MaxMTU: 1200})
	require.Error(t, rangeErr)

	assert.Equal(t, 1420, computeWireGuardSafeMTU(1500))
	assert.Equal(t, 1412, computeWireGuardSafeMTU(1492))
	assert.Equal(t, 1340, computeWireGuardSafeMTU(1420))
	assert.Equal(t, 0, computeWireGuardSafeMTU(80))
	assert.Equal(t, 0, computeWireGuardSafeMTU(0))
}

type mtuSearchTestCase struct {
	name          string
	ip            net.IP
	minMTU        int
	maxMTU        int
	ceiling       int
	silentDrop    bool
	wantMTU       int
	wantBlackhole bool
	wantHdrBytes  int
	wantFirstMTUs []int
}

func runMTUSearchCases(t *testing.T, cases []mtuSearchTestCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			discovered, steps, blackhole, fallback := discoverMTUWithProber(ctx, tc.ip, tc.minMTU, tc.maxMTU, func(_ context.Context, _ net.IP, wireMTU int) mtuStepAttempt {
				if wireMTU <= tc.ceiling {
					return mtuStepAttempt{step: MTUStep{Success: true, RTTMs: 1.5}, confirmed: true}
				}
				if tc.silentDrop {
					return mtuStepAttempt{step: MTUStep{Error: "timeout"}, timedOut: true}
				}
				return mtuStepAttempt{step: MTUStep{Error: "EMSGSIZE"}, emsgsize: true}
			})

			assert.False(t, fallback)
			assert.Equal(t, tc.wantMTU, discovered)
			assert.Equal(t, tc.wantBlackhole, blackhole)
			require.GreaterOrEqual(t, len(steps), len(tc.wantFirstMTUs))
			for i, wantMTU := range tc.wantFirstMTUs {
				assert.Equal(t, wantMTU, steps[i].WireMTU)
			}
			for i := range steps {
				assert.Equal(t, steps[i].WireMTU-tc.wantHdrBytes, steps[i].PayloadSize)
			}
		})
	}
}

func TestMTUBinarySearchStepMath(t *testing.T) {
	t.Parallel()
	runMTUSearchCases(t, []mtuSearchTestCase{
		{
			name:          "standard 1500 succeeds on first step",
			ip:            net.ParseIP("192.0.2.10"),
			minMTU:        576,
			maxMTU:        1500,
			ceiling:       1500,
			wantMTU:       1500,
			wantHdrBytes:  28,
			wantFirstMTUs: []int{1500},
		},
		{
			name:          "pppoe 1492 exact discovery",
			ip:            net.ParseIP("192.0.2.10"),
			minMTU:        576,
			maxMTU:        1500,
			ceiling:       1492,
			wantMTU:       1492,
			wantHdrBytes:  28,
			wantFirstMTUs: []int{1500, 1492},
		},
		{
			name:          "non-standard 1450 binary search between 1420 and 1492",
			ip:            net.ParseIP("192.0.2.10"),
			minMTU:        576,
			maxMTU:        1500,
			ceiling:       1450,
			wantMTU:       1450,
			wantHdrBytes:  28,
			wantFirstMTUs: []int{1500, 1492, 1420},
		},
		{
			name:          "sub-1420 bottleneck 1350 binary search",
			ip:            net.ParseIP("2001:db8::1"),
			minMTU:        576,
			maxMTU:        1500,
			ceiling:       1350,
			wantMTU:       1350,
			wantHdrBytes:  48,
			wantFirstMTUs: []int{1500, 1492, 1420, 1280},
		},
	})
}

func TestMTUBinarySearchBlackholeAndEdgeCases(t *testing.T) {
	t.Parallel()
	runMTUSearchCases(t, []mtuSearchTestCase{
		{
			name:          "wireguard 1420 with silent blackhole drop above ceiling",
			ip:            net.ParseIP("192.0.2.10"),
			minMTU:        576,
			maxMTU:        1500,
			ceiling:       1420,
			silentDrop:    true,
			wantMTU:       1420,
			wantBlackhole: true,
			wantHdrBytes:  28,
			wantFirstMTUs: []int{1500, 1492, 1420},
		},
		{
			name:          "ipv6 min 1280",
			ip:            net.ParseIP("2001:db8::1"),
			minMTU:        576,
			maxMTU:        1500,
			ceiling:       1280,
			wantMTU:       1280,
			wantHdrBytes:  48,
			wantFirstMTUs: []int{1500, 1492, 1420, 1280},
		},
		{
			name:          "constrained 900 binary search between 576 and 1280",
			ip:            net.ParseIP("192.0.2.10"),
			minMTU:        576,
			maxMTU:        1500,
			ceiling:       900,
			wantMTU:       900,
			wantHdrBytes:  28,
			wantFirstMTUs: []int{1500, 1492, 1420, 1280, 576},
		},
		{
			name:          "all candidates rejected by EMSGSIZE",
			ip:            net.ParseIP("192.0.2.10"),
			minMTU:        576,
			maxMTU:        1500,
			ceiling:       400,
			wantMTU:       0,
			wantHdrBytes:  28,
			wantFirstMTUs: []int{1500, 1492, 1420, 1280, 576},
		},
	})
}

func TestExecuteMTUProbeLoopbackUDPAndICMPFallback(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	udpRes, err := ExecuteMTUProbe(ctx, MTUProbeParams{
		Target:   "127.0.0.1",
		MinMTU:   576,
		MaxMTU:   1500,
		Protocol: "udp",
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", udpRes.Target)
	assert.Equal(t, "127.0.0.1", udpRes.ResolvedIP)
	assert.Contains(t, []string{"udp_df", "udp_fallback", "tcp_mss_estimate", "tcp_connect"}, udpRes.ProbeMode)
	assert.Equal(t, 1500, udpRes.DiscoveredMTU)
	assert.Equal(t, 1420, udpRes.WireGuardSafeMTU)
	assert.False(t, udpRes.BlackholeDetected)
	assert.NotEmpty(t, udpRes.Steps)
	_, tsErr := time.Parse(time.RFC3339, udpRes.Timestamp)
	require.NoError(t, tsErr)

	icmpRes, err := ExecuteMTUProbe(ctx, MTUProbeParams{
		Target:   "127.0.0.1",
		MinMTU:   576,
		MaxMTU:   1500,
		Protocol: "icmp",
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", icmpRes.ResolvedIP)
	assert.Contains(t, []string{"icmp_df", "tcp_mss_estimate", "tcp_connect"}, icmpRes.ProbeMode)
	assert.Equal(t, 1500, icmpRes.DiscoveredMTU)
	assert.Equal(t, 1420, icmpRes.WireGuardSafeMTU)
	assert.NotEmpty(t, icmpRes.Steps)
}

func TestMTRParamsClamping(t *testing.T) {
	t.Parallel()

	maxHops, cycles, timeout := normalizeMTRParams(MTRParams{})
	assert.Equal(t, 15, maxHops)
	assert.Equal(t, 5, cycles)
	assert.Equal(t, 1500*time.Millisecond, timeout)

	maxHops, cycles, timeout = normalizeMTRParams(MTRParams{MaxHops: -3, Cycles: -1, TimeoutMS: 10})
	assert.Equal(t, 1, maxHops)
	assert.Equal(t, 1, cycles)
	assert.Equal(t, 100*time.Millisecond, timeout)

	maxHops, cycles, timeout = normalizeMTRParams(MTRParams{MaxHops: 99, Cycles: 50, TimeoutMS: 20000})
	assert.Equal(t, 30, maxHops)
	assert.Equal(t, 10, cycles)
	assert.Equal(t, 5000*time.Millisecond, timeout)
}

func TestComputeMTRHopStats(t *testing.T) {
	t.Parallel()

	lost := computeMTRHopStats(2, 5, "", nil)
	assert.Equal(t, 2, lost.Hop)
	assert.Equal(t, "*", lost.IP)
	assert.Equal(t, 5, lost.Sent)
	assert.Equal(t, 0, lost.Received)
	assert.InDelta(t, 100.0, lost.LossPct, 1e-9)
	assert.InDelta(t, 0.0, lost.AvgMs, 1e-9)

	single := computeMTRHopStats(1, 1, "192.0.2.1", []float64{12.5})
	assert.Equal(t, "192.0.2.1", single.IP)
	assert.Equal(t, 1, single.Received)
	assert.InDelta(t, 0.0, single.LossPct, 1e-9)
	assert.InDelta(t, 12.5, single.LastMs, 1e-9)
	assert.InDelta(t, 12.5, single.AvgMs, 1e-9)
	assert.InDelta(t, 12.5, single.BestMs, 1e-9)
	assert.InDelta(t, 12.5, single.WorstMs, 1e-9)
	assert.InDelta(t, 0.0, single.StDevMs, 1e-9)

	partial := computeMTRHopStats(3, 5, "198.51.100.1", []float64{10.0, 20.0, 30.0, 20.0})
	assert.Equal(t, 3, partial.Hop)
	assert.Equal(t, 5, partial.Sent)
	assert.Equal(t, 4, partial.Received)
	assert.InDelta(t, 20.0, partial.LossPct, 1e-9)
	assert.InDelta(t, 20.0, partial.LastMs, 1e-9)
	assert.InDelta(t, 20.0, partial.AvgMs, 1e-9)
	assert.InDelta(t, 10.0, partial.BestMs, 1e-9)
	assert.InDelta(t, 30.0, partial.WorstMs, 1e-9)
	assert.InDelta(t, math.Sqrt(50.0), partial.StDevMs, 1e-9)
}

func TestExtractEmbeddedEchoAndMatchICMPMTRReply(t *testing.T) {
	t.Parallel()

	// IPv4 header with IHL=6 (24 bytes, includes 4B IP options) + 8-byte ICMP Echo.
	v4Pkt := make([]byte, 32)
	v4Pkt[0] = (4 << 4) | 6
	v4Pkt[9] = mtrICMPProtoV4
	binary.BigEndian.PutUint16(v4Pkt[28:30], 0x1234)
	binary.BigEndian.PutUint16(v4Pkt[30:32], 42)

	id, seq, ok := extractEmbeddedEchoIDSeq(v4Pkt, true)
	require.True(t, ok)
	assert.Equal(t, 0x1234, id)
	assert.Equal(t, 42, seq)

	teMsg := &icmp.Message{
		Type: ipv4.ICMPTypeTimeExceeded,
		Body: &icmp.TimeExceeded{Data: v4Pkt},
	}
	matched, reached := matchICMPMTRReply(teMsg, true, 0x1234, 42, "192.0.2.1", "192.0.2.99")
	assert.True(t, matched)
	assert.False(t, reached)

	matchedWrong, _ := matchICMPMTRReply(teMsg, true, 0x1234, 99, "192.0.2.1", "192.0.2.99")
	assert.False(t, matchedWrong)

	// IPv6 header (40 bytes) + 8-byte ICMPv6 Echo.
	v6Pkt := make([]byte, 48)
	v6Pkt[0] = 6 << 4
	v6Pkt[6] = mtrICMPProtoV6
	binary.BigEndian.PutUint16(v6Pkt[44:46], 0xabcd)
	binary.BigEndian.PutUint16(v6Pkt[46:48], 7)

	id6, seq6, ok6 := extractEmbeddedEchoIDSeq(v6Pkt, false)
	require.True(t, ok6)
	assert.Equal(t, 0xabcd, id6)
	assert.Equal(t, 7, seq6)

	v6EchoReply := &icmp.Message{
		Type: ipv6.ICMPTypeEchoReply,
		Body: &icmp.Echo{ID: 0xabcd, Seq: 7},
	}
	matched6, reached6 := matchICMPMTRReply(v6EchoReply, false, 0xabcd, 7, "2001:db8::1", "2001:db8::1")
	assert.True(t, matched6)
	assert.True(t, reached6)

	_, _, truncatedOK := extractEmbeddedEchoIDSeq(v4Pkt[:10], true)
	assert.False(t, truncatedOK)
}

func TestExecuteMTRQualityLoopbackAndBoundedPTR(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := ExecuteMTRQuality(ctx, MTRParams{
		Target:    "127.0.0.1",
		MaxHops:   3,
		Cycles:    3,
		TimeoutMS: 200,
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", res.Target)
	assert.Equal(t, "127.0.0.1", res.ResolvedIP)
	assert.Contains(t, []string{"icmp", "tcp_traceroute_fallback"}, res.ProbeMode)
	assert.Equal(t, 3, res.Cycles)
	assert.Equal(t, 3, res.MaxHops)
	assert.True(t, res.Reached)
	require.NotEmpty(t, res.Hops)

	lastHop := res.Hops[len(res.Hops)-1]
	assert.Equal(t, "127.0.0.1", lastHop.IP)
	assert.Equal(t, 3, lastHop.Sent)
	assert.Equal(t, 3, lastHop.Received)
	assert.InDelta(t, 0.0, lastHop.LossPct, 1e-9)
	assert.LessOrEqual(t, lastHop.BestMs, lastHop.AvgMs)
	assert.LessOrEqual(t, lastHop.AvgMs, lastHop.WorstMs)
	assert.GreaterOrEqual(t, lastHop.StDevMs, 0.0)
	_, tsErr := time.Parse(time.RFC3339, res.Timestamp)
	require.NoError(t, tsErr)

	// Verify bounded PTR concurrency (> 8 hops) completes cleanly without races.
	manyHops := make([]MTRHop, 12)
	for i := range manyHops {
		manyHops[i] = MTRHop{Hop: i + 1, IP: "127.0.0.1"}
		if i%3 == 0 {
			manyHops[i].IP = "*"
		}
	}
	resolveMTRHopHostnames(ctx, manyHops)
	assert.Empty(t, manyHops[0].Hostname)
	assert.NotEmpty(t, manyHops[1].Hostname)
}
