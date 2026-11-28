//go:build linux

package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/sys/unix"
)

type (
	tcpHopOutcome struct {
		hopIP            string
		rttMs            float64
		matched, reached bool
	}
	tcpPendingProbe struct {
		start time.Time
		done  chan struct{}
		res   tcpHopOutcome
	}
	tcpWaveSession struct {
		isIPv4    bool
		dst4      [4]byte
		dst6      [16]byte
		targetStr string
		tr        *icmpTransport
		mu        sync.Mutex
		pending   map[uint32]*tcpPendingProbe
	}
)

func executeTCPWaveMTR(ctx context.Context, targetIP net.IP, maxHops, cycles int, timeout time.Duration) *MTRResult {
	if targetIP == nil || targetIP.To16() == nil {
		return &MTRResult{ProbeMode: "tcp_traceroute_fallback"}
	}
	maxHops, cycles = clampMTRParam(maxHops, 15, 1, 255), max(cycles, 1)
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	tr, hasRawICMP := openICMPTransport(targetIP)
	if !hasRawICMP {
		return executeDirectTCPFallback(ctx, targetIP, cycles, timeout)
	}
	sess := &tcpWaveSession{isIPv4: targetIP.To4() != nil, targetStr: targetIP.String(), tr: tr, pending: make(map[uint32]*tcpPendingProbe, maxHops)}
	copy(sess.dst4[:], targetIP.To4())
	copy(sess.dst6[:], targetIP.To16())
	readerDone := make(chan struct{})
	go sess.readICMP(ctx, readerDone)
	defer func() { _ = tr.conn.Close(); <-readerDone }()
	accs := make([]hopAccumulator, maxHops)
	activeMaxHops, reached, activePort, mode, executedCycles := maxHops, false, uint16(443), "tcp_443", 0
	runWave := func(dstPort uint16) ([]tcpHopOutcome, bool, int) {
		outcomes := make([]tcpHopOutcome, activeMaxHops)
		var wg sync.WaitGroup
		for i := range activeMaxHops {
			wg.Go(func() { outcomes[i] = sess.probeHop(ctx, i+1, dstPort, timeout) })
		}
		wg.Wait()
		waveReached, score := false, 0
		for i := range outcomes {
			if outcomes[i].matched {
				score++
				waveReached = waveReached || outcomes[i].reached
			}
		}
		return outcomes, waveReached, score
	}
	for cycle := 0; cycle < cycles && ctx.Err() == nil; cycle++ {
		executedCycles = cycle + 1
		outcomes, waveReached, score := runWave(activePort)
		if cycle == 0 && !waveReached && ctx.Err() == nil {
			if alt, altReached, altScore := runWave(80); altReached || (ctx.Err() == nil && altScore > score) {
				outcomes, activePort, mode = alt, 80, "tcp_80"
			}
		}
		for i, out := range outcomes {
			accs[i].sent++
			if out.matched {
				if accs[i].ip == "" {
					accs[i].ip = out.hopIP
				}
				accs[i].rttsMs = append(accs[i].rttsMs, out.rttMs)
				if out.reached {
					reached, activeMaxHops = true, min(activeMaxHops, i+1)
				}
			}
		}
	}
	hops := make([]MTRHop, activeMaxHops)
	for i := range activeMaxHops {
		hops[i] = computeMTRHopStats(i+1, accs[i].sent, accs[i].ip, accs[i].rttsMs)
	}
	return &MTRResult{ProbeMode: mode, Cycles: executedCycles, Reached: reached, Hops: hops}
}

func (s *tcpWaveSession) probeHop(ctx context.Context, ttl int, dstPort uint16, timeout time.Duration) tcpHopOutcome {
	dom, lvl, opt, bindSA, dstSA := unix.AF_INET, unix.IPPROTO_IP, unix.IP_TTL, unix.Sockaddr(&unix.SockaddrInet4{}), unix.Sockaddr(&unix.SockaddrInet4{Port: int(dstPort), Addr: s.dst4})
	if !s.isIPv4 {
		dom, lvl, opt, bindSA, dstSA = unix.AF_INET6, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, &unix.SockaddrInet6{}, &unix.SockaddrInet6{Port: int(dstPort), Addr: s.dst6}
	}
	fd, err := unix.Socket(dom, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	var srcPort int
	if err == nil && fd >= 0 && fd <= math.MaxInt32 &&
		unix.SetsockoptLinger(fd, unix.SOL_SOCKET, unix.SO_LINGER, &unix.Linger{Onoff: 1, Linger: 0}) == nil &&
		unix.SetsockoptInt(fd, lvl, opt, ttl) == nil && unix.Bind(fd, bindSA) == nil {
		if sa, gErr := unix.Getsockname(fd); gErr == nil {
			switch sa := sa.(type) {
			case *unix.SockaddrInet4:
				srcPort = sa.Port
			case *unix.SockaddrInet6:
				srcPort = sa.Port
			}
		}
	}
	if srcPort <= 0 || srcPort > math.MaxUint16 {
		if err == nil && fd >= 0 {
			_ = unix.Close(fd)
		}
		return tcpHopOutcome{}
	}
	key, start := (uint32(srcPort)<<16)|uint32(dstPort), time.Now()
	probe := &tcpPendingProbe{start: start, done: make(chan struct{})}
	s.mu.Lock()
	s.pending[key] = probe
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, key)
		s.mu.Unlock()
		_ = unix.Close(fd)
	}()
	if err = unix.Connect(fd, dstSA); err == nil || errors.Is(err, unix.ECONNREFUSED) {
		return tcpHopOutcome{hopIP: s.targetStr, rttMs: float64(time.Since(start)) / float64(time.Millisecond), matched: true, reached: true}
	}
	if !errors.Is(err, unix.EINPROGRESS) && !errors.Is(err, unix.EALREADY) {
		return tcpHopOutcome{}
	}
	deadline := start.Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if fd < 0 || fd > math.MaxInt32 {
		return tcpHopOutcome{}
	}
	// #nosec G115 -- fd is explicitly bounds-checked to [0, math.MaxInt32] above.
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
pollLoop:
	for ctx.Err() == nil {
		select {
		case <-probe.done:
			break pollLoop
		default:
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			break
		}
		waitMS := max(int(min(rem, 40*time.Millisecond)/time.Millisecond), 1)
		n, pErr := unix.Poll(fds, waitMS)
		if pErr != nil && !errors.Is(pErr, unix.EINTR) {
			break
		}
		if pErr == nil && n > 0 && fds[0].Revents&(unix.POLLOUT|unix.POLLERR|unix.POLLHUP) != 0 {
			soErr, sockErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if sockErr == nil && ((soErr == 0 && fds[0].Revents&(unix.POLLOUT|unix.POLLERR) == unix.POLLOUT) || soErr == int(unix.ECONNREFUSED)) {
				return tcpHopOutcome{hopIP: s.targetStr, rttMs: float64(time.Since(start)) / float64(time.Millisecond), matched: true, reached: true}
			}
			if sockErr != nil || (soErr != int(unix.EINPROGRESS) && soErr != int(unix.EALREADY)) {
				if grace := min(time.Until(deadline), 25*time.Millisecond); grace > 0 {
					t := time.NewTimer(grace)
					select {
					case <-probe.done:
					case <-t.C:
					case <-ctx.Done():
					}
					t.Stop()
				}
				break
			}
		}
	}
	s.mu.Lock()
	out := probe.res
	s.mu.Unlock()
	return out
}

func (s *tcpWaveSession) readICMP(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	buf := make([]byte, 1500)
	for ctx.Err() == nil {
		n, peer, err := s.tr.conn.ReadFrom(buf)
		if err != nil {
			if !isTimeoutErr(err) || ctx.Err() != nil {
				return
			}
			continue
		}
		now := time.Now()
		rm, parseErr := icmp.ParseMessage(s.tr.protoNum, buf[:n])
		if parseErr != nil {
			continue
		}
		peerIP, reached := peerIPString(peer), false
		var data []byte
		switch body := rm.Body.(type) {
		case *icmp.TimeExceeded:
			data = body.Data
		case *icmp.DstUnreach:
			data, reached = body.Data, peerIP == s.targetStr
		default:
			continue
		}
		off := ipv6HeaderLen
		if s.isIPv4 && len(data) >= ipv4HeaderLen {
			off = int(data[0]&0x0f) * 4
		}
		if len(data) < off+l4HeaderLen || (s.isIPv4 && (off < ipv4HeaderLen || data[9] != unix.IPPROTO_TCP)) || (!s.isIPv4 && data[6] != unix.IPPROTO_TCP) {
			continue
		}
		key := (uint32(binary.BigEndian.Uint16(data[off:off+2])) << 16) | uint32(binary.BigEndian.Uint16(data[off+2:off+4]))
		s.mu.Lock()
		if p := s.pending[key]; p != nil {
			delete(s.pending, key)
			p.res = tcpHopOutcome{hopIP: peerIP, rttMs: max(float64(now.Sub(p.start))/float64(time.Millisecond), 0), matched: true, reached: reached}
			close(p.done)
		}
		s.mu.Unlock()
	}
}

func executeDirectTCPFallback(ctx context.Context, targetIP net.IP, cycles int, timeout time.Duration) *MTRResult {
	ports, rttsMs := []string{"443", "80", "22", "53"}, make([]float64, 0, cycles)
	sent, preferred, mode, hopIP, targetStr := 0, "", "tcp_traceroute_fallback", "*", targetIP.String()
	for cycle := 0; cycle < cycles && ctx.Err() == nil; cycle++ {
		sent++
		perAttempt := timeout
		if preferred == "" {
			perAttempt = max(timeout/time.Duration(len(ports)), 25*time.Millisecond)
		}
		dialer := net.Dialer{Timeout: perAttempt}
		refusedRTT, refusedPort := 0.0, ""
		for i := 0; i < len(ports) && ctx.Err() == nil; i++ {
			port := ports[i]
			if preferred != "" && port != preferred {
				continue
			}
			start := time.Now()
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(targetStr, port))
			rtt := float64(time.Since(start)) / float64(time.Millisecond)
			if err == nil {
				_ = conn.Close()
				refusedPort, refusedRTT = port, rtt
				break
			}
			if (isConnRefusedErr(err) || errors.Is(err, unix.ECONNREFUSED)) && refusedPort == "" {
				refusedPort, refusedRTT = port, rtt
			}
		}
		if refusedPort != "" {
			if preferred = refusedPort; preferred == "443" || preferred == "80" {
				mode = "tcp_" + preferred
			}
			hopIP, rttsMs = targetStr, append(rttsMs, refusedRTT)
		}
	}
	return &MTRResult{ProbeMode: mode, Cycles: sent, Reached: len(rttsMs) > 0, Hops: []MTRHop{computeMTRHopStats(1, sent, hopIP, rttsMs)}}
}
