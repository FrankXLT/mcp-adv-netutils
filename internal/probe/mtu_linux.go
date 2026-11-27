//go:build linux

package probe

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	icmpProtocolV4 = 1
	icmpProtocolV6 = 58
)

var icmpSeqCounter atomic.Uint64

func probePathMTU(ctx context.Context, ip net.IP, minMTU, maxMTU int, proto string) (*MTUProbeResult, error) {
	probeFn := probeLinuxUDPDF
	probeMode := "udp_df"
	if proto == "icmp" {
		probeFn = probeLinuxICMPDF
		probeMode = "icmp_df"
	}

	discovered, steps, blackhole, fallbackSuggested := discoverMTUWithProber(ctx, ip, minMTU, maxMTU, probeFn)
	if fallbackSuggested && ctx.Err() == nil {
		return tcpMSSEstimateProbe(ctx, ip, minMTU, maxMTU), nil
	}

	return &MTUProbeResult{
		ProbeMode:         probeMode,
		DiscoveredMTU:     discovered,
		Steps:             steps,
		BlackholeDetected: blackhole,
	}, nil
}

func linuxDFControl(isIPv4 bool) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		if ctrlErr := c.Control(func(fd uintptr) {
			if fd > math.MaxInt {
				sockErr = errors.New("file descriptor exceeds int range")
				return
			}
			sockFD := int(fd)
			if isIPv4 {
				sockErr = unix.SetsockoptInt(sockFD, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
				return
			}
			sockErr = unix.SetsockoptInt(sockFD, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
		}); ctrlErr != nil {
			return fmt.Errorf("raw socket control failed: %w", ctrlErr)
		}
		if sockErr != nil {
			return fmt.Errorf("setsockopt PMTU discover failed: %w", sockErr)
		}
		return nil
	}
}

func probeLinuxUDPDF(ctx context.Context, ip net.IP, wireMTU int) mtuStepAttempt {
	isIPv4 := ip.To4() != nil
	network := "udp4"
	if !isIPv4 {
		network = "udp6"
	}

	stepCtx, cancel := context.WithTimeout(ctx, defaultStepTimeout)
	defer cancel()

	dialer := &net.Dialer{
		Timeout: defaultStepTimeout,
		Control: linuxDFControl(isIPv4),
	}
	conn, err := dialer.DialContext(stepCtx, network, net.JoinHostPort(ip.String(), defaultProbePort))
	if err != nil {
		return classifySocketDialErr(err)
	}
	defer func() { _ = conn.Close() }()

	payloadSize := maxPayloadForMTU(wireMTU, headerSizeForIP(ip))
	payload := make([]byte, payloadSize)
	start := time.Now()
	_ = conn.SetDeadline(start.Add(defaultStepTimeout))

	if _, writeErr := conn.Write(payload); writeErr != nil {
		return classifyWriteErr(writeErr, time.Since(start))
	}

	buf := make([]byte, 256)
	_, readErr := conn.Read(buf)
	rttMs := float64(time.Since(start)) / float64(time.Millisecond)

	switch {
	case readErr == nil:
		return mtuStepAttempt{step: MTUStep{Success: true, RTTMs: rttMs}, confirmed: true}
	case errors.Is(readErr, unix.EMSGSIZE):
		return mtuStepAttempt{step: MTUStep{Error: "EMSGSIZE: path MTU exceeded", RTTMs: rttMs}, emsgsize: true}
	case isConnRefusedErr(readErr) || errors.Is(readErr, unix.ECONNREFUSED):
		return mtuStepAttempt{step: MTUStep{Success: true, RTTMs: rttMs}, confirmed: true}
	case isTimeoutErr(readErr):
		if pmtu := readSocketPMTU(conn, isIPv4); pmtu > 0 && pmtu < wireMTU {
			return mtuStepAttempt{
				step:     MTUStep{Error: fmt.Sprintf("EMSGSIZE: kernel PMTU reduced to %d", pmtu), RTTMs: rttMs},
				emsgsize: true,
			}
		}
		return mtuStepAttempt{
			step:     MTUStep{Error: "probe timed out (no reply or ICMP fragmentation needed)", RTTMs: rttMs},
			timedOut: true,
		}
	default:
		return mtuStepAttempt{step: MTUStep{Error: readErr.Error(), RTTMs: rttMs}}
	}
}

func probeLinuxICMPDF(ctx context.Context, ip net.IP, wireMTU int) mtuStepAttempt {
	isIPv4 := ip.To4() != nil
	network := "ip4:icmp"
	listenAddr := "0.0.0.0"
	protoNum := icmpProtocolV4
	var echoType icmp.Type = ipv4.ICMPTypeEcho
	if !isIPv4 {
		network = "ip6:ipv6-icmp"
		listenAddr = "::"
		protoNum = icmpProtocolV6
		echoType = ipv6.ICMPTypeEchoRequest
	}

	lc := net.ListenConfig{Control: linuxDFControl(isIPv4)}
	conn, err := lc.ListenPacket(ctx, network, listenAddr)
	if err != nil {
		return classifySocketDialErr(err)
	}
	defer func() { _ = conn.Close() }()

	probeID := safeICMPProbeID()
	seq := int(icmpSeqCounter.Add(1) & 0xffff)
	payloadSize := maxPayloadForMTU(wireMTU, headerSizeForIP(ip))

	msg := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   probeID,
			Seq:  seq,
			Data: make([]byte, payloadSize),
		},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return mtuStepAttempt{step: MTUStep{Error: fmt.Sprintf("marshal ICMP failed: %v", err)}}
	}

	start := time.Now()
	if _, writeErr := conn.WriteTo(msgBytes, &net.IPAddr{IP: ip}); writeErr != nil {
		return classifyWriteErr(writeErr, time.Since(start))
	}

	return waitICMPDFReply(ctx, conn, protoNum, isIPv4, probeID, seq, start)
}

func waitICMPDFReply(
	ctx context.Context,
	conn net.PacketConn,
	protoNum int,
	isIPv4 bool,
	probeID, seq int,
	start time.Time,
) mtuStepAttempt {
	deadline := start.Add(defaultStepTimeout)
	if ctxDeadline, hasDeadline := ctx.Deadline(); hasDeadline && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetReadDeadline(deadline)

	buf := make([]byte, absMaxMTU+128)
	for {
		n, _, err := conn.ReadFrom(buf)
		rttMs := float64(time.Since(start)) / float64(time.Millisecond)
		if err != nil {
			if errors.Is(err, unix.EMSGSIZE) {
				return mtuStepAttempt{step: MTUStep{Error: "EMSGSIZE: path MTU exceeded", RTTMs: rttMs}, emsgsize: true}
			}
			return mtuStepAttempt{
				step:     MTUStep{Error: err.Error(), RTTMs: rttMs},
				timedOut: isTimeoutErr(err),
			}
		}

		rm, parseErr := icmp.ParseMessage(protoNum, buf[:n])
		if parseErr != nil {
			continue
		}

		if isEchoReplyMatch(rm, isIPv4, probeID, seq) {
			return mtuStepAttempt{step: MTUStep{Success: true, RTTMs: rttMs}, confirmed: true}
		}
		if isPacketTooBigMsg(rm, isIPv4) {
			return mtuStepAttempt{
				step:     MTUStep{Error: "EMSGSIZE: ICMP fragmentation needed / packet too big", RTTMs: rttMs},
				emsgsize: true,
			}
		}
	}
}

func isEchoReplyMatch(rm *icmp.Message, isIPv4 bool, probeID, seq int) bool {
	expected := icmp.Type(ipv4.ICMPTypeEchoReply)
	if !isIPv4 {
		expected = ipv6.ICMPTypeEchoReply
	}
	if rm.Type != expected {
		return false
	}
	echo, ok := rm.Body.(*icmp.Echo)
	return ok && echo.ID == probeID && echo.Seq == seq
}

func isPacketTooBigMsg(rm *icmp.Message, isIPv4 bool) bool {
	if isIPv4 {
		return rm.Type == ipv4.ICMPTypeDestinationUnreachable && rm.Code == 4
	}
	return rm.Type == ipv6.ICMPTypePacketTooBig
}

func readSocketPMTU(conn net.Conn, isIPv4 bool) int {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return 0
	}

	var pmtu int
	_ = rawConn.Control(func(fd uintptr) {
		if fd > math.MaxInt {
			return
		}
		sockFD := int(fd)
		if isIPv4 {
			if val, sockErr := unix.GetsockoptInt(sockFD, unix.IPPROTO_IP, unix.IP_MTU); sockErr == nil {
				pmtu = val
			}
			return
		}
		if val, sockErr := unix.GetsockoptInt(sockFD, unix.IPPROTO_IPV6, unix.IPV6_MTU); sockErr == nil {
			pmtu = val
		}
	})
	return pmtu
}

func tcpMSSEstimateProbe(ctx context.Context, ip net.IP, minMTU, maxMTU int) *MTUProbeResult {
	isIPv4 := ip.To4() != nil
	ifaceMTU := discoverOutboundInterfaceMTU(ctx, ip)
	estMTU, rttMs, reachable := probeTCPMSSAndReachability(ctx, ip, isIPv4)

	if !reachable {
		return &MTUProbeResult{
			ProbeMode:     "tcp_mss_estimate",
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
	if estMTU > 0 && estMTU < ceiling {
		ceiling = estMTU
	}

	discovered, steps, _, _ := discoverMTUWithProber(ctx, ip, minMTU, maxMTU, func(_ context.Context, _ net.IP, wireMTU int) mtuStepAttempt {
		if wireMTU <= ceiling {
			return mtuStepAttempt{
				step:      MTUStep{Success: true, RTTMs: rttMs},
				confirmed: true,
			}
		}
		return mtuStepAttempt{
			step:     MTUStep{Error: fmt.Sprintf("exceeds estimated path ceiling (%d)", ceiling), RTTMs: rttMs},
			emsgsize: true,
		}
	})

	return &MTUProbeResult{
		ProbeMode:         "tcp_mss_estimate",
		DiscoveredMTU:     discovered,
		Steps:             steps,
		BlackholeDetected: false,
	}
}

func probeTCPMSSAndReachability(ctx context.Context, ip net.IP, isIPv4 bool) (int, float64, bool) {
	ports := []string{"443", "80", "22"}
	ipTCPHdr := ipv4HeaderLen + tcpHeaderLen
	if !isIPv4 {
		ipTCPHdr = ipv6HeaderLen + tcpHeaderLen
	}

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
			mss := readTCPMaxSeg(conn)
			_ = conn.Close()
			if mss > 0 {
				return mss + ipTCPHdr, rttMs, true
			}
			return 0, rttMs, true
		}
		if isConnRefusedErr(err) && !refusedSeen {
			refusedSeen = true
			refusedRTT = rttMs
		}
	}

	if refusedSeen {
		return 0, refusedRTT, true
	}
	return 0, 0, false
}

func readTCPMaxSeg(conn net.Conn) int {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return 0
	}
	var mss int
	_ = rawConn.Control(func(fd uintptr) {
		if fd > math.MaxInt {
			return
		}
		if val, sockErr := unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG); sockErr == nil {
			mss = val
		}
	})
	return mss
}

func classifySocketDialErr(err error) mtuStepAttempt {
	if isLinuxPermOrSockOptErr(err) {
		return mtuStepAttempt{step: MTUStep{Error: err.Error()}, permDenied: true}
	}
	if errors.Is(err, unix.EMSGSIZE) {
		return mtuStepAttempt{step: MTUStep{Error: err.Error()}, emsgsize: true}
	}
	return mtuStepAttempt{step: MTUStep{Error: err.Error()}, timedOut: isTimeoutErr(err)}
}

func classifyWriteErr(err error, elapsed time.Duration) mtuStepAttempt {
	rttMs := float64(elapsed) / float64(time.Millisecond)
	if errors.Is(err, unix.EMSGSIZE) {
		return mtuStepAttempt{step: MTUStep{Error: "EMSGSIZE: exceeds path or interface MTU", RTTMs: rttMs}, emsgsize: true}
	}
	if isLinuxPermOrSockOptErr(err) {
		return mtuStepAttempt{step: MTUStep{Error: err.Error(), RTTMs: rttMs}, permDenied: true}
	}
	return mtuStepAttempt{step: MTUStep{Error: err.Error(), RTTMs: rttMs}, timedOut: isTimeoutErr(err)}
}

func isLinuxPermOrSockOptErr(err error) bool {
	return errors.Is(err, os.ErrPermission) ||
		errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.ENOPROTOOPT)
}

func safeICMPProbeID() int {
	pid := os.Getpid()
	if pid < 0 {
		return 1
	}
	return pid & 0xffff
}
