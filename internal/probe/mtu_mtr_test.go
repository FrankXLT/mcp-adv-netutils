package probe

import (
	"context"
	"encoding/binary"
	"math"
	"net"
	"sync"
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
	assert.Equal(t, 4, cycles)
	assert.Equal(t, 900*time.Millisecond, timeout)

	maxHops, cycles, timeout = normalizeMTRParams(MTRParams{MaxHops: -3, Cycles: -1, TimeoutMS: 10})
	assert.Equal(t, 1, maxHops)
	assert.Equal(t, 1, cycles)
	assert.Equal(t, 100*time.Millisecond, timeout)

	maxHops, cycles, timeout = normalizeMTRParams(MTRParams{MaxHops: 99, Cycles: 50, TimeoutMS: 20000})
	assert.Equal(t, 30, maxHops)
	assert.Equal(t, 10, cycles)
	assert.Equal(t, 5000*time.Millisecond, timeout)

	maxHops, cycles, timeout = normalizeMTRParams(MTRParams{MaxHops: 1, Cycles: 1, TimeoutMS: 100})
	assert.Equal(t, 1, maxHops)
	assert.Equal(t, 1, cycles)
	assert.Equal(t, 100*time.Millisecond, timeout)

	maxHops, cycles, timeout = normalizeMTRParams(MTRParams{MaxHops: 30, Cycles: 10, TimeoutMS: 5000})
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
	assert.Contains(t, []string{"icmp", "tcp_443", "tcp_80", "tcp_traceroute_fallback"}, res.ProbeMode)
	assert.Equal(t, 3, res.Cycles)
	assert.Equal(t, 3, res.MaxHops)
	assert.True(t, res.Reached)
	require.NotEmpty(t, res.Hops)

	lastHop := res.Hops[len(res.Hops)-1]
	assert.Equal(t, "127.0.0.1", lastHop.IP)
	assert.Equal(t, "Destination", lastHop.Segment)
	assert.Equal(t, 3, lastHop.Sent)
	assert.Equal(t, 3, lastHop.Received)
	assert.InDelta(t, 0.0, lastHop.LossPct, 1e-9)
	assert.InDelta(t, 0.0, res.DestLossPct, 1e-9)
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

func TestICMPMTRProbeIDSeqUniqueness(t *testing.T) {
	t.Parallel()

	type idSeqPair struct{ id, seq int }
	seenAll := make(map[idSeqPair]struct{}, 120)
	for cycle := range 4 {
		seenIDs := make(map[int]struct{}, 30)
		for hop := 1; hop <= 30; hop++ {
			id, seq := icmpMTRProbeIDSeq(0x1357, cycle, hop)
			assert.NotContains(t, seenIDs, id, "duplicate ID in cycle %d hop %d", cycle, hop)
			seenIDs[id] = struct{}{}

			pair := idSeqPair{id: id, seq: seq}
			assert.NotContains(t, seenAll, pair, "duplicate (ID, Seq) at cycle %d hop %d", cycle, hop)
			seenAll[pair] = struct{}{}
		}
	}
}

func TestICMPWaveDemuxEchoAndTimeExceeded(t *testing.T) {
	t.Parallel()

	now := time.Now()
	w := &icmpWaveState{
		limitHops:   4,
		sendingDone: true,
		entries: []icmpWaveEntry{
			{sent: true, sentAt: now.Add(-15 * time.Millisecond)},
			{sent: true, sentAt: now.Add(-12 * time.Millisecond)},
			{sent: true, sentAt: now.Add(-8 * time.Millisecond)},
			{sent: true, sentAt: now.Add(-5 * time.Millisecond)},
		},
		byKey: map[icmpProbeKey]int{
			{id: 0x1001, seq: 1}: 0,
			{id: 0x1102, seq: 2}: 1,
			{id: 0x1203, seq: 3}: 2,
			{id: 0x1304, seq: 4}: 3,
		},
		done: make(chan struct{}),
	}

	// Outgoing EchoRequest looped back on raw socket must be ignored.
	reqMsg := &icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 0x1203, Seq: 3}}
	_, _, _, reqValid := extractICMPWaveReply(reqMsg, true, "93.184.216.34", "93.184.216.34")
	assert.False(t, reqValid)

	// IPv4 TimeExceeded (IHL=6 options) for hop 1.
	tePkt := make([]byte, 32)
	tePkt[0] = (4 << 4) | 6
	tePkt[9] = mtrICMPProtoV4
	binary.BigEndian.PutUint16(tePkt[28:30], 0x1001)
	binary.BigEndian.PutUint16(tePkt[30:32], 1)
	teMsg := &icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Body: &icmp.TimeExceeded{Data: tePkt}}
	id1, seq1, reached1, ok1 := extractICMPWaveReply(teMsg, true, "192.168.1.1", "93.184.216.34")
	require.True(t, ok1)
	assert.False(t, reached1)
	w.recordReply(id1, seq1, "192.168.1.1", reached1, now)

	// IPv4 EchoReply for hop 3 (target reached before hop 2 arrives).
	echoReply := &icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: 0x1203, Seq: 3}}
	id3, seq3, reached3, ok3 := extractICMPWaveReply(echoReply, true, "93.184.216.34", "93.184.216.34")
	require.True(t, ok3)
	assert.True(t, reached3)
	w.recordReply(id3, seq3, "93.184.216.34", reached3, now)
	assert.Equal(t, 3, w.minReached)

	// Wave must not complete until hop 2 also matches.
	select {
	case <-w.done:
		t.Fatal("wave marked done before intermediate hop 2 matched")
	default:
	}

	// IPv6 TimeExceeded demux check.
	v6Pkt := make([]byte, 48)
	v6Pkt[0] = 6 << 4
	v6Pkt[6] = mtrICMPProtoV6
	binary.BigEndian.PutUint16(v6Pkt[44:46], 0xabcd)
	binary.BigEndian.PutUint16(v6Pkt[46:48], 2)
	v6TE := &icmp.Message{Type: ipv6.ICMPTypeTimeExceeded, Body: &icmp.TimeExceeded{Data: v6Pkt}}
	idV6, seqV6, reachedV6, okV6 := extractICMPWaveReply(v6TE, false, "2001:db8::1", "2001:db8::99")
	require.True(t, okV6)
	assert.Equal(t, 0xabcd, idV6)
	assert.Equal(t, 2, seqV6)
	assert.False(t, reachedV6)

	// Complete hop 2 -> wave done closes immediately without waiting for hop 4.
	binary.BigEndian.PutUint16(tePkt[28:30], 0x1102)
	binary.BigEndian.PutUint16(tePkt[30:32], 2)
	id2, seq2, reached2, ok2 := extractICMPWaveReply(teMsg, true, "10.0.0.1", "93.184.216.34")
	require.True(t, ok2)
	w.recordReply(id2, seq2, "10.0.0.1", reached2, now)

	<-w.done
	assert.Equal(t, "192.168.1.1", w.entries[0].hopIP)
	assert.Equal(t, "10.0.0.1", w.entries[1].hopIP)
	assert.Equal(t, "93.184.216.34", w.entries[2].hopIP)
	assert.True(t, w.entries[2].reached)
}

func TestFinalizeMTRMetadataAndSelection(t *testing.T) {
	t.Parallel()

	targetIP := net.ParseIP("93.184.216.34")
	reachedRes := &MTRResult{
		ProbeMode: "icmp",
		Reached:   true,
		Hops: []MTRHop{
			{Hop: 1, IP: "192.168.1.1", Sent: 4, Received: 4},
			{Hop: 2, IP: "*", Sent: 4, Received: 0, LossPct: 100},
			{Hop: 3, IP: "203.0.113.5", Sent: 4, Received: 4},
			{Hop: 4, IP: "*", Sent: 4, Received: 0, LossPct: 100},
			{Hop: 5, IP: "93.184.216.34", Sent: 4, Received: 4, LossPct: 0},
			{Hop: 6, IP: "*", Sent: 4, Received: 0, LossPct: 100},
			{Hop: 7, IP: "*", Sent: 4, Received: 0, LossPct: 100},
		},
	}
	finalizeMTRMetadata(reachedRes, targetIP)
	require.Len(t, reachedRes.Hops, 5)
	assert.Equal(t, "Gateway", reachedRes.Hops[0].Segment)
	assert.False(t, reachedRes.Hops[0].Silent)
	assert.Equal(t, "Transit", reachedRes.Hops[1].Segment)
	assert.True(t, reachedRes.Hops[1].Silent)
	assert.False(t, reachedRes.Hops[2].Silent)
	assert.True(t, reachedRes.Hops[3].Silent)
	assert.Equal(t, "Destination", reachedRes.Hops[4].Segment)
	assert.False(t, reachedRes.Hops[4].Silent)
	assert.Equal(t, 2, reachedRes.SilentTransitHops)
	assert.InDelta(t, 0.0, reachedRes.DestLossPct, 1e-9)

	unreachedRes := &MTRResult{
		ProbeMode: "icmp",
		Reached:   false,
		Hops: []MTRHop{
			{Hop: 1, IP: "10.0.0.1", Sent: 1, Received: 1},
			{Hop: 2, IP: "*", Sent: 1, Received: 0, LossPct: 100},
			{Hop: 3, IP: "198.51.100.1", Sent: 1, Received: 1},
			{Hop: 4, IP: "*", Sent: 1, Received: 0, LossPct: 100},
			{Hop: 5, IP: "*", Sent: 1, Received: 0, LossPct: 100},
		},
	}
	finalizeMTRMetadata(unreachedRes, targetIP)
	require.Len(t, unreachedRes.Hops, 5)
	assert.True(t, unreachedRes.Hops[1].Silent)
	assert.False(t, unreachedRes.Hops[3].Silent)
	assert.False(t, unreachedRes.Hops[4].Silent)
	assert.Equal(t, 1, unreachedRes.SilentTransitHops)
	assert.InDelta(t, 100.0, unreachedRes.DestLossPct, 1e-9)

	// Escalation selection: prefer reached TCP, else ICMP if it saw more intermediate hops.
	tcpReached := &MTRResult{ProbeMode: "tcp_443", Reached: true, Hops: []MTRHop{{Hop: 1, IP: "93.184.216.34", Received: 4}}}
	assert.Equal(t, "tcp_443", selectWinningMTRResult(unreachedRes, true, tcpReached).ProbeMode)

	tcpEmpty := &MTRResult{ProbeMode: "tcp_traceroute_fallback", Reached: false, Hops: []MTRHop{{Hop: 1, IP: "*", Received: 0}}}
	assert.Equal(t, "icmp", selectWinningMTRResult(unreachedRes, true, tcpEmpty).ProbeMode)
	assert.Equal(t, "tcp_traceroute_fallback", selectWinningMTRResult(&MTRResult{ProbeMode: "icmp", Hops: []MTRHop{{Hop: 1, IP: "*", Received: 0}}}, true, tcpEmpty).ProbeMode)

	// Additional selectWinningMTRResult edge branches: !hasICMP, nil inputs, ties, tcp > icmp.
	assert.Equal(t, "tcp_443", selectWinningMTRResult(unreachedRes, false, tcpReached).ProbeMode)
	assert.Equal(t, "tcp_traceroute_fallback", selectWinningMTRResult(nil, false, nil).ProbeMode)
	assert.Equal(t, "tcp_traceroute_fallback", selectWinningMTRResult(nil, true, tcpEmpty).ProbeMode)
	assert.Equal(t, "icmp", selectWinningMTRResult(unreachedRes, true, nil).ProbeMode)

	tcpTwoHops := &MTRResult{
		ProbeMode: "tcp_80",
		Reached:   false,
		Hops:      []MTRHop{{Hop: 1, IP: "10.0.0.1", Received: 1}, {Hop: 2, IP: "10.0.0.2", Received: 1}},
	}
	assert.Equal(t, "tcp_80", selectWinningMTRResult(unreachedRes, true, tcpTwoHops).ProbeMode)
	tcpThreeHops := &MTRResult{
		ProbeMode: "tcp_443",
		Reached:   false,
		Hops:      []MTRHop{{Hop: 1, Received: 1}, {Hop: 2, Received: 1}, {Hop: 3, Received: 1}},
	}
	assert.Equal(t, "tcp_443", selectWinningMTRResult(unreachedRes, true, tcpThreeHops).ProbeMode)
}

func TestExecuteTCPTracerouteLoopbackAndNilGuards(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Nil context, nil IP, and invalid-length IP guards.
	//nolint:staticcheck // Intentionally verifying nil context guard.
	nilCtxRes := ExecuteTCPTraceroute(nil, net.ParseIP("127.0.0.1"), 3, 2, 200*time.Millisecond)
	require.NotNil(t, nilCtxRes)
	assert.False(t, nilCtxRes.Reached)
	assert.Equal(t, "tcp_traceroute_fallback", nilCtxRes.ProbeMode)
	assert.InDelta(t, 100.0, nilCtxRes.DestLossPct, 1e-9)

	nilIPRes := ExecuteTCPTraceroute(ctx, nil, 3, 2, 200*time.Millisecond)
	require.NotNil(t, nilIPRes)
	assert.False(t, nilIPRes.Reached)
	assert.InDelta(t, 100.0, nilIPRes.DestLossPct, 1e-9)

	badIPRes := ExecuteTCPTraceroute(ctx, net.IP{1, 2}, 3, 2, 200*time.Millisecond)
	require.NotNil(t, badIPRes)
	assert.False(t, badIPRes.Reached)

	// Loopback IPv4 execution via ExecuteTCPTraceroute.
	res := ExecuteTCPTraceroute(ctx, net.ParseIP("127.0.0.1"), 3, 2, 250*time.Millisecond)
	require.NotNil(t, res)
	assert.Contains(t, []string{"tcp_443", "tcp_80", "tcp_traceroute_fallback"}, res.ProbeMode)
	assert.Equal(t, "127.0.0.1", res.ResolvedIP)
	assert.Equal(t, 3, res.MaxHops)
	assert.Equal(t, 2, res.Cycles)
	assert.True(t, res.Reached)
	require.NotEmpty(t, res.Hops)
	last := res.Hops[len(res.Hops)-1]
	assert.Equal(t, "127.0.0.1", last.IP)
	assert.Equal(t, "Destination", last.Segment)
	assert.InDelta(t, 0.0, res.DestLossPct, 1e-9)
	_, tsErr := time.Parse(time.RFC3339, res.Timestamp)
	require.NoError(t, tsErr)
}

func TestICMPWaveConcurrentRecordReplyAndSummaryRead(t *testing.T) {
	t.Parallel()

	const hopsCount = 12
	now := time.Now()
	w := &icmpWaveState{
		limitHops:   hopsCount,
		sendingDone: true,
		entries:     make([]icmpWaveEntry, hopsCount),
		byKey:       make(map[icmpProbeKey]int, hopsCount),
		done:        make(chan struct{}),
	}
	for i := range hopsCount {
		id, seq := icmpMTRProbeIDSeq(0x2468, 0, i+1)
		w.entries[i] = icmpWaveEntry{sent: true, sentAt: now.Add(-10 * time.Millisecond)}
		w.byKey[icmpProbeKey{id: id, seq: seq}] = i
	}

	var wg sync.WaitGroup
	// Concurrent reply writers + markFailed + locked summary readers exercising -race safety.
	for i := range hopsCount {
		wg.Go(func() {
			id, seq := icmpMTRProbeIDSeq(0x2468, 0, i+1)
			if i == hopsCount-1 {
				w.markFailed(i+1, id, seq)
				return
			}
			isDest := i == hopsCount-2
			ip := "10.0.0.1"
			if isDest {
				ip = "93.184.216.34"
			}
			w.recordReply(id, seq, ip, isDest, now)
		})
	}
	for range 4 {
		wg.Go(func() {
			for range 10 {
				w.mu.Lock()
				matched := 0
				for j := range w.entries {
					if w.entries[j].matched {
						matched++
					}
				}
				w.mu.Unlock()
				assert.LessOrEqual(t, matched, hopsCount)
			}
		})
	}
	wg.Wait()
	<-w.done

	w.mu.Lock()
	for i := range hopsCount - 1 {
		assert.True(t, w.entries[i].matched)
	}
	assert.True(t, w.entries[hopsCount-2].reached)
	assert.True(t, w.entries[hopsCount-1].failed)
	w.mu.Unlock()
}
