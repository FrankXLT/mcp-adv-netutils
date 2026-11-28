package traceroute

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/probe"
)

const defaultProbesPerHop = 2

func executeProbeCascade(ctx context.Context, target, resolvedIP string, maxHops, timeoutSec int, deps execDeps) (*TracerouteResponse, error) {
	cmdPath, lookErr := deps.lookPath("traceroute")
	targetArg := target
	if resolvedIP != "" {
		targetArg = resolvedIP
	}

	var icmpResp, tcpResp, udpResp *TracerouteResponse
	var icmpErr, udpErr error

	if lookErr == nil {
		icmpResp, icmpErr = runCLIProbe(ctx, cmdPath, target, resolvedIP, targetArg, maxHops, timeoutSec, true, deps)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, canceledProbeErr(ctxErr, icmpErr)
		}
		if icmpErr == nil && icmpResp != nil && icmpResp.ReachedDestination {
			return icmpResp, nil
		}
	}

	if ip := net.ParseIP(resolvedIP); ip != nil && deps.tcpFallbackFunc != nil {
		mtrRes := deps.tcpFallbackFunc(ctx, ip, maxHops, time.Duration(timeoutSec)*time.Second)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("traceroute canceled: %w", ctxErr)
		}
		tcpResp = convertMTRToTraceroute(mtrRes, target, resolvedIP, maxHops)
		if tcpResp != nil && tcpResp.ReachedDestination {
			return tcpResp, nil
		}
	}

	if lookErr == nil {
		udpResp, udpErr = runCLIProbe(ctx, cmdPath, target, resolvedIP, targetArg, maxHops, timeoutSec, false, deps)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, canceledProbeErr(ctxErr, udpErr)
		}
	}

	best := selectBestTraceroute(icmpResp, tcpResp, udpResp)
	if best == nil || (len(best.Hops) == 0 && !best.ReachedDestination) {
		for _, err := range []error{icmpErr, udpErr, lookErr} {
			if err != nil {
				return nil, err
			}
		}
		if best == nil {
			return nil, errors.New("traceroute failed: no probe results")
		}
	}
	return best, nil
}

func canceledProbeErr(ctxErr, opErr error) error {
	if opErr != nil {
		return opErr
	}
	return fmt.Errorf("traceroute canceled: %w", ctxErr)
}

func runCLIProbe(ctx context.Context, cmdPath, target, resolvedIP, targetArg string, maxHops, timeoutSec int, isICMP bool, deps execDeps) (*TracerouteResponse, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, time.Duration(maxHops*timeoutSec+5)*time.Second)
	defer cancel()

	args, probeMode := make([]string, 0, 10), "udp"
	if isICMP {
		args, probeMode = append(args, "-I"), "icmp"
	}
	args = append(args, "-n", "-q", strconv.Itoa(defaultProbesPerHop), "-w", strconv.Itoa(timeoutSec), "-m", strconv.Itoa(maxHops), "--", targetArg)

	cmd := deps.commandContext(cmdCtx, cmdPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to execute traceroute: %w", err)
	}
	hops, reached, scanErr := parseTracerouteOutput(stdout, target, resolvedIP)
	waitErr := cmd.Wait()
	if scanErr != nil {
		return nil, fmt.Errorf("failed reading traceroute output: %w", scanErr)
	}
	if err := evaluateWaitError(ctx, cmdCtx, waitErr, len(hops)); err != nil {
		return nil, err
	}
	return &TracerouteResponse{
		Target: target, ResolvedIP: resolvedIP, ProbeMode: probeMode, MaxHops: maxHops,
		Hops: hops, ReachedDestination: reached, Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func evaluateWaitError(ctx, cmdCtx context.Context, waitErr error, hopCount int) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		if waitErr != nil {
			return fmt.Errorf("traceroute canceled: %w", waitErr)
		}
		return fmt.Errorf("traceroute canceled: %w", ctxErr)
	}
	if waitErr != nil && (cmdCtx.Err() != nil || hopCount == 0) {
		return fmt.Errorf("traceroute failed: %w", waitErr)
	}
	return nil
}

func convertMTRToTraceroute(mtr *probe.MTRResult, target, resolvedIP string, maxHops int) *TracerouteResponse {
	if mtr == nil {
		return nil
	}
	mode := orDefaultStr(mtr.ProbeMode, "tcp_traceroute_fallback")
	target = orDefaultStr(target, mtr.Target)
	resolvedIP = orDefaultStr(resolvedIP, mtr.ResolvedIP)
	if maxHops <= 0 {
		maxHops = mtr.MaxHops
	}

	hops := make([]HopResult, 0, len(mtr.Hops))
	for i := range mtr.Hops {
		mh := &mtr.Hops[i]
		var rtts []float64
		if mh.Received == 2 && (mh.BestMs > 0 || mh.WorstMs > 0) {
			rtts = []float64{mh.BestMs, mh.WorstMs}
		} else if mh.Received > 0 {
			rtts = make([]float64, mh.Received)
			for j := range rtts {
				rtts[j] = mh.AvgMs
			}
		}
		hops = append(hops, HopResult{
			Hop: mh.Hop, IP: orDefaultStr(mh.IP, "*"), Hostname: mh.Hostname, Segment: mh.Segment,
			Silent: mh.Silent, RTTMs: rtts, AvgRTTMs: mh.AvgMs, TimedOut: mh.Received == 0,
		})
	}
	return &TracerouteResponse{
		Target: target, ResolvedIP: resolvedIP, ProbeMode: mode, MaxHops: maxHops, Hops: hops,
		ReachedDestination: mtr.Reached, SilentTransitHops: mtr.SilentTransitHops,
		DestLossPct: mtr.DestLossPct, Timestamp: orDefaultStr(mtr.Timestamp, time.Now().UTC().Format(time.RFC3339)),
	}
}

func orDefaultStr(val, fallback string) string {
	if val != "" {
		return val
	}
	return fallback
}

func selectBestTraceroute(candidates ...*TracerouteResponse) *TracerouteResponse {
	for _, c := range candidates {
		if c != nil && c.ReachedDestination {
			return c
		}
	}
	var best *TracerouteResponse
	bestResp := -1
	for _, c := range candidates {
		if c == nil {
			continue
		}
		respCount := 0
		for i := range c.Hops {
			if len(c.Hops[i].RTTMs) > 0 {
				respCount++
			}
		}
		if best == nil || respCount > bestResp || (respCount == bestResp && len(c.Hops) > len(best.Hops)) {
			best, bestResp = c, respCount
		}
	}
	return best
}

func finalizeTracerouteResult(resp *TracerouteResponse, resolvedIP net.IP) {
	if resp == nil {
		return
	}
	targetStr := resp.ResolvedIP
	if resolvedIP != nil {
		targetStr = resolvedIP.String()
	}
	resp.Hops = trimTrailingSilentHops(resp.Hops, resp.ReachedDestination, targetStr, resp.Target)

	lastRespIdx := -1
	for i := range resp.Hops {
		if len(resp.Hops[i].RTTMs) > 0 {
			lastRespIdx = i
		}
	}
	silentCount, totalHops := 0, len(resp.Hops)
	for i := range resp.Hops {
		h := &resp.Hops[i]
		if len(h.RTTMs) == 0 && (i < lastRespIdx || (resp.ReachedDestination && i < totalHops-1)) {
			h.Silent = true
			silentCount++
		} else {
			h.Silent = false
		}
		h.Segment = assignHopSegment(i, h, targetStr, resp.Target, totalHops, resp.ReachedDestination)
	}
	resp.SilentTransitHops = silentCount
	resp.DestLossPct = computeDestLossPct(resp.Hops, resp.ReachedDestination)
}

func trimTrailingSilentHops(hops []HopResult, reached bool, targetStr, rawTarget string) []HopResult {
	if !reached || len(hops) == 0 {
		return hops
	}
	destIdx, lastRespIdx := -1, -1
	for i := range hops {
		if len(hops[i].RTTMs) == 0 {
			continue
		}
		lastRespIdx = i
		if destIdx == -1 && ((targetStr != "" && hops[i].IP == targetStr) || (rawTarget != "" && hops[i].IP == rawTarget)) {
			destIdx = i
		}
	}
	trimIdx := lastRespIdx
	if destIdx >= 0 {
		trimIdx = destIdx
	}
	if trimIdx >= 0 && trimIdx+1 < len(hops) {
		return hops[:trimIdx+1]
	}
	return hops
}

func assignHopSegment(hopIdx int, h *HopResult, targetStr, rawTarget string, totalHops int, reached bool) string {
	if (targetStr != "" && h.IP == targetStr) || (rawTarget != "" && h.IP == rawTarget) || (reached && hopIdx == totalHops-1) {
		return "Destination"
	}
	if hopIdx == 0 {
		if ip := net.ParseIP(h.IP); ip != nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLoopback()) {
			return "Gateway"
		}
	}
	return "Transit"
}

func computeDestLossPct(hops []HopResult, reached bool) float64 {
	if !reached {
		return 100.0
	}
	if len(hops) == 0 {
		return 0.0
	}
	n := len(hops[len(hops)-1].RTTMs)
	if n == 0 {
		return 100.0
	}
	if n >= defaultProbesPerHop {
		return 0.0
	}
	return float64(defaultProbesPerHop-n) / float64(defaultProbesPerHop) * 100.0
}
