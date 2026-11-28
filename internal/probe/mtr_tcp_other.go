//go:build !linux

package probe

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"
)

func executeTCPWaveMTR(ctx context.Context, targetIP net.IP, _, cycles int, timeout time.Duration) *MTRResult {
	if targetIP == nil || targetIP.To16() == nil {
		return &MTRResult{ProbeMode: "tcp_traceroute_fallback"}
	}
	if cycles < 1 {
		cycles = 1
	}
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	ports := []string{"443", "80", "22", "53"}
	rttsMs := make([]float64, 0, cycles)
	sent, preferredPort, reached := 0, "", false
	targetStr := targetIP.String()

	for range cycles {
		if ctx.Err() != nil {
			break
		}
		sent++

		rttMs, usedPort, ok := probeDirectTCPWaveCycle(ctx, targetStr, ports, preferredPort, timeout)
		if ok {
			reached = true
			if preferredPort == "" {
				preferredPort = usedPort
			}
			rttsMs = append(rttsMs, rttMs)
		}
	}

	hop := computeMTRHopStats(1, sent, targetStr, rttsMs)
	if !reached {
		hop.IP = "*"
	}

	mode := "tcp_traceroute_fallback"
	if preferredPort == "443" || preferredPort == "80" {
		mode = "tcp_" + preferredPort
	}
	return &MTRResult{ProbeMode: mode, Reached: reached, Hops: []MTRHop{hop}}
}

func probeDirectTCPWaveCycle(
	ctx context.Context,
	targetStr string,
	ports []string,
	preferredPort string,
	timeout time.Duration,
) (float64, string, bool) {
	perAttempt := timeout
	if preferredPort == "" {
		perAttempt = max(timeout/time.Duration(len(ports)), 25*time.Millisecond)
	}

	var refusedRTT float64
	var refusedPort string

	for _, port := range ports {
		if ctx.Err() != nil {
			break
		}
		if preferredPort != "" && port != preferredPort {
			continue
		}
		dialCtx, cancel := context.WithTimeout(ctx, perAttempt)
		start := time.Now()
		conn, err := (&net.Dialer{Timeout: perAttempt}).DialContext(dialCtx, "tcp", net.JoinHostPort(targetStr, port))
		cancel()
		rttMs := float64(time.Since(start)) / float64(time.Millisecond)

		if err == nil {
			_ = conn.Close()
			return rttMs, port, true
		}
		if (isConnRefusedErr(err) || errors.Is(err, syscall.ECONNREFUSED)) && refusedPort == "" {
			refusedPort = port
			refusedRTT = rttMs
		}
	}

	if refusedPort != "" {
		return refusedRTT, refusedPort, true
	}
	return 0, "", false
}
