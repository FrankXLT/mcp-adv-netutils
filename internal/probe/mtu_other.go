//go:build !linux

package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

func probePathMTU(ctx context.Context, ip net.IP, minMTU, maxMTU int, proto string) (*MTUProbeResult, error) {
	if proto == "icmp" {
		return tcpConnectMTUProbe(ctx, ip, minMTU, maxMTU), nil
	}

	ifaceMTU := discoverOutboundInterfaceMTU(ctx, ip)
	discovered, steps, blackhole, fallbackSuggested := discoverMTUWithProber(ctx, ip, minMTU, maxMTU, func(stepCtx context.Context, targetIP net.IP, wireMTU int) mtuStepAttempt {
		if ifaceMTU > 0 && wireMTU > ifaceMTU {
			return mtuStepAttempt{
				step:     MTUStep{Error: fmt.Sprintf("EMSGSIZE: exceeds local interface MTU (%d)", ifaceMTU)},
				emsgsize: true,
			}
		}
		return probeFallbackUDP(stepCtx, targetIP, wireMTU)
	})

	if fallbackSuggested && ctx.Err() == nil {
		return tcpConnectMTUProbe(ctx, ip, minMTU, maxMTU), nil
	}

	return &MTUProbeResult{
		ProbeMode:         "udp_fallback",
		DiscoveredMTU:     discovered,
		Steps:             steps,
		BlackholeDetected: blackhole,
	}, nil
}

func probeFallbackUDP(ctx context.Context, ip net.IP, wireMTU int) mtuStepAttempt {
	network := "udp4"
	if ip != nil && ip.To4() == nil {
		network = "udp6"
	}

	stepCtx, cancel := context.WithTimeout(ctx, defaultStepTimeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: defaultStepTimeout}
	conn, err := dialer.DialContext(stepCtx, network, net.JoinHostPort(ip.String(), defaultProbePort))
	if err != nil {
		if errors.Is(err, syscall.EMSGSIZE) {
			return mtuStepAttempt{step: MTUStep{Error: err.Error()}, emsgsize: true}
		}
		return mtuStepAttempt{step: MTUStep{Error: err.Error()}, timedOut: isTimeoutErr(err)}
	}
	defer func() { _ = conn.Close() }()

	payloadSize := maxPayloadForMTU(wireMTU, headerSizeForIP(ip))
	payload := make([]byte, payloadSize)
	start := time.Now()
	_ = conn.SetDeadline(start.Add(defaultStepTimeout))

	if _, writeErr := conn.Write(payload); writeErr != nil {
		rttMs := float64(time.Since(start)) / float64(time.Millisecond)
		if errors.Is(writeErr, syscall.EMSGSIZE) {
			return mtuStepAttempt{step: MTUStep{Error: "EMSGSIZE: exceeds interface MTU", RTTMs: rttMs}, emsgsize: true}
		}
		return mtuStepAttempt{step: MTUStep{Error: writeErr.Error(), RTTMs: rttMs}, timedOut: isTimeoutErr(writeErr)}
	}

	buf := make([]byte, 256)
	_, readErr := conn.Read(buf)
	rttMs := float64(time.Since(start)) / float64(time.Millisecond)

	switch {
	case readErr == nil:
		return mtuStepAttempt{step: MTUStep{Success: true, RTTMs: rttMs}, confirmed: true}
	case errors.Is(readErr, syscall.EMSGSIZE):
		return mtuStepAttempt{step: MTUStep{Error: "EMSGSIZE: path MTU exceeded", RTTMs: rttMs}, emsgsize: true}
	case isConnRefusedErr(readErr) || errors.Is(readErr, syscall.ECONNREFUSED):
		return mtuStepAttempt{step: MTUStep{Success: true, RTTMs: rttMs}, confirmed: true}
	case isTimeoutErr(readErr):
		return mtuStepAttempt{step: MTUStep{Error: "probe timed out", RTTMs: rttMs}, timedOut: true}
	default:
		return mtuStepAttempt{step: MTUStep{Error: readErr.Error(), RTTMs: rttMs}}
	}
}

func tcpConnectMTUProbe(ctx context.Context, ip net.IP, minMTU, maxMTU int) *MTUProbeResult {
	ifaceMTU := discoverOutboundInterfaceMTU(ctx, ip)
	rttMs, reachable := probeTCPReachabilityFallback(ctx, ip)

	if !reachable {
		return &MTUProbeResult{
			ProbeMode:     "tcp_connect",
			DiscoveredMTU: 0,
			Steps: []MTUStep{
				{
					PayloadSize: maxPayloadForMTU(maxMTU, headerSizeForIP(ip)),
					WireMTU:     maxMTU,
					Success:     false,
					Error:       "target unreachable on TCP fallback ports",
				},
			},
		}
	}

	ceiling := maxMTU
	if ifaceMTU > 0 && ifaceMTU < ceiling {
		ceiling = ifaceMTU
	}

	discovered, steps, _, _ := discoverMTUWithProber(ctx, ip, minMTU, maxMTU, func(_ context.Context, _ net.IP, wireMTU int) mtuStepAttempt {
		if wireMTU <= ceiling {
			return mtuStepAttempt{
				step:      MTUStep{Success: true, RTTMs: rttMs},
				confirmed: true,
			}
		}
		return mtuStepAttempt{
			step:     MTUStep{Error: fmt.Sprintf("exceeds interface MTU ceiling (%d)", ceiling), RTTMs: rttMs},
			emsgsize: true,
		}
	})

	return &MTUProbeResult{
		ProbeMode:         "tcp_connect",
		DiscoveredMTU:     discovered,
		Steps:             steps,
		BlackholeDetected: false,
	}
}

func probeTCPReachabilityFallback(ctx context.Context, ip net.IP) (float64, bool) {
	ports := []string{"443", "80", "22"}
	var refusedRTT float64
	var refusedSeen bool

	for _, port := range ports {
		if ctx.Err() != nil {
			break
		}
		dialCtx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
		start := time.Now()
		conn, err := (&net.Dialer{Timeout: 400 * time.Millisecond}).DialContext(dialCtx, "tcp", net.JoinHostPort(ip.String(), port))
		cancel()
		rttMs := float64(time.Since(start)) / float64(time.Millisecond)

		if err == nil {
			_ = conn.Close()
			return rttMs, true
		}
		if (isConnRefusedErr(err) || errors.Is(err, syscall.ECONNREFUSED)) && !refusedSeen {
			refusedSeen = true
			refusedRTT = rttMs
		}
	}

	if refusedSeen {
		return refusedRTT, true
	}
	return 0, false
}
