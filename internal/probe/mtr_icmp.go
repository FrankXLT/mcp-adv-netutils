package probe

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type (
	icmpProbeKey struct {
		id, seq int
	}
	icmpWaveEntry struct {
		sent, failed, matched bool
		reached               bool
		sentAt                time.Time
		hopIP                 string
		rttMs                 float64
	}
	icmpWaveState struct {
		mu                    sync.Mutex
		limitHops, minReached int
		sendingDone           bool
		entries               []icmpWaveEntry
		byKey                 map[icmpProbeKey]int
		done                  chan struct{}
		once                  sync.Once
	}
)

const icmpStaggerStep = 5 * time.Millisecond

var icmpMTRBaseCounter atomic.Uint32

func executeICMPMTR(ctx context.Context, targetIP net.IP, maxHops, cycles int, timeout time.Duration) (*MTRResult, bool) {
	tr, ok := openICMPTransport(targetIP)
	if !ok {
		return nil, false
	}
	if err := tr.setHopLimit(1); err != nil {
		_ = tr.conn.Close()
		return nil, false
	}

	targetStr := targetIP.String()
	var waveMu sync.RWMutex
	var activeWave *icmpWaveState
	readerDone := make(chan struct{})
	go readICMPWaveReplies(ctx, tr, targetStr, &waveMu, &activeWave, readerDone)
	defer func() {
		_ = tr.conn.Close()
		<-readerDone
	}()

	accs := make([]hopAccumulator, maxHops)
	baseID := (max(os.Getpid(), 1) + int(icmpMTRBaseCounter.Add(1)&0xffff)*4099) & 0xffff
	activeMaxHops, reached, executedCycles := maxHops, false, 0

	for cycle := 0; cycle < cycles && ctx.Err() == nil; cycle++ {
		executedCycles = cycle + 1
		w := runICMPWave(ctx, tr, targetIP, &waveMu, &activeWave, baseID, cycle, activeMaxHops, timeout)
		w.mu.Lock()
		for i := range w.entries {
			e := &w.entries[i]
			if !e.sent {
				continue
			}
			accs[i].sent++
			if !e.matched {
				continue
			}
			if accs[i].ip == "" {
				accs[i].ip = e.hopIP
			}
			accs[i].rttsMs = append(accs[i].rttsMs, e.rttMs)
			if e.reached {
				reached = true
				activeMaxHops = min(activeMaxHops, i+1)
			}
		}
		w.mu.Unlock()
		if cycle == 0 && !reached {
			break
		}
	}

	hops := make([]MTRHop, activeMaxHops)
	for i := range activeMaxHops {
		hops[i] = computeMTRHopStats(i+1, accs[i].sent, accs[i].ip, accs[i].rttsMs)
	}
	hops = trimTrailingSilentHops(hops, reached, targetStr)
	return &MTRResult{ProbeMode: "icmp", Cycles: executedCycles, Reached: reached, Hops: hops}, true
}

func icmpMTRProbeIDSeq(baseID, cycle, hop int) (int, int) {
	return (baseID + hop*257 + cycle*31) & 0xffff, (cycle*100 + hop) & 0xffff
}

func runICMPWave(ctx context.Context, tr *icmpTransport, targetIP net.IP, waveMu *sync.RWMutex, activeWave **icmpWaveState, baseID, cycle, maxHops int, timeout time.Duration) *icmpWaveState {
	w := &icmpWaveState{limitHops: maxHops, entries: make([]icmpWaveEntry, maxHops), byKey: make(map[icmpProbeKey]int, maxHops), done: make(chan struct{})}
	waveMu.Lock()
	*activeWave = w
	waveMu.Unlock()
	defer func() {
		waveMu.Lock()
		*activeWave = nil
		waveMu.Unlock()
	}()

	waveDeadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(waveDeadline) {
		waveDeadline = ctxDeadline
	}
	stopSend, senderDone := make(chan struct{}), make(chan struct{})
	go func() {
		dst, sentCount := &net.IPAddr{IP: targetIP}, 0
		defer func() {
			w.mu.Lock()
			w.sendingDone = true
			w.limitHops = min(w.limitHops, sentCount)
			w.checkCompleteLocked()
			w.mu.Unlock()
			close(senderDone)
		}()
		for hop := 1; hop <= maxHops; hop++ {
			if hop > 1 && !waitICMPStagger(ctx, stopSend, w.done) {
				return
			}
			id, seq := icmpMTRProbeIDSeq(baseID, cycle, hop)
			msgBytes, err := (&icmp.Message{Type: tr.echoType, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("mcp-adv-netutils-mtr")}}).Marshal(nil)
			if err != nil {
				continue
			}
			w.mu.Lock()
			if w.minReached > 0 && hop > w.minReached {
				w.mu.Unlock()
				return
			}
			w.entries[hop-1].sent, w.entries[hop-1].sentAt = true, time.Now()
			w.byKey[icmpProbeKey{id: id, seq: seq}] = hop - 1
			w.mu.Unlock()
			sentCount = hop
			if err = tr.setHopLimit(hop); err == nil {
				_, err = tr.conn.WriteTo(msgBytes, dst)
			}
			if err != nil {
				w.markFailed(hop, id, seq)
			}
		}
	}()

	timer := time.NewTimer(max(time.Until(waveDeadline), 0))
	defer timer.Stop()
	select {
	case <-w.done:
	case <-timer.C:
	case <-ctx.Done():
	}
	close(stopSend)
	<-senderDone
	return w
}

func waitICMPStagger(ctx context.Context, stopSend, waveDone <-chan struct{}) bool {
	timer := time.NewTimer(icmpStaggerStep)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-stopSend:
		return false
	case <-waveDone:
		return false
	case <-ctx.Done():
		return false
	}
}

func readICMPWaveReplies(ctx context.Context, tr *icmpTransport, targetStr string, waveMu *sync.RWMutex, activeWave **icmpWaveState, done chan<- struct{}) {
	defer close(done)
	buf := make([]byte, 1500)
	for ctx.Err() == nil {
		n, peer, err := tr.conn.ReadFrom(buf)
		if err != nil {
			if !isTimeoutErr(err) || ctx.Err() != nil {
				return
			}
			continue
		}
		now := time.Now()
		rm, parseErr := icmp.ParseMessage(tr.protoNum, buf[:n])
		if parseErr != nil {
			continue
		}
		waveMu.RLock()
		w := *activeWave
		waveMu.RUnlock()
		if w == nil {
			continue
		}
		peerIP := peerIPString(peer)
		if id, seq, reachedDest, valid := extractICMPWaveReply(rm, tr.isIPv4, peerIP, targetStr); valid {
			w.recordReply(id, seq, peerIP, reachedDest, now)
		}
	}
}

func (w *icmpWaveState) markFailed(hop, id, seq int) {
	w.mu.Lock()
	delete(w.byKey, icmpProbeKey{id: id, seq: seq})
	w.entries[hop-1].failed = true
	w.checkCompleteLocked()
	w.mu.Unlock()
}

func (w *icmpWaveState) recordReply(id, seq int, peerIP string, isDestReply bool, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	idx, ok := w.byKey[icmpProbeKey{id: id, seq: seq}]
	if !ok {
		return
	}
	delete(w.byKey, icmpProbeKey{id: id, seq: seq})
	e := &w.entries[idx]
	if !e.matched {
		e.matched = true
		e.hopIP = peerIP
		e.rttMs = max(float64(now.Sub(e.sentAt))/float64(time.Millisecond), 0)
		e.reached = isDestReply
		if isDestReply && (w.minReached == 0 || idx+1 < w.minReached) {
			w.minReached = idx + 1
		}
	}
	w.checkCompleteLocked()
}

func (w *icmpWaveState) checkCompleteLocked() {
	limit := w.limitHops
	if w.minReached > 0 {
		limit = w.minReached
	} else if !w.sendingDone {
		return
	}
	for i := range limit {
		if !w.entries[i].matched && !w.entries[i].failed {
			return
		}
	}
	w.once.Do(func() { close(w.done) })
}

func extractICMPWaveReply(rm *icmp.Message, isIPv4 bool, peerIP, targetStr string) (int, int, bool, bool) {
	if rm == nil {
		return 0, 0, false, false
	}
	switch body := rm.Body.(type) {
	case *icmp.Echo:
		if (isIPv4 && rm.Type == ipv4.ICMPTypeEchoReply) || (!isIPv4 && rm.Type == ipv6.ICMPTypeEchoReply) {
			return body.ID, body.Seq, peerIP == targetStr, true
		}
	case *icmp.TimeExceeded:
		if (isIPv4 && rm.Type == ipv4.ICMPTypeTimeExceeded) || (!isIPv4 && rm.Type == ipv6.ICMPTypeTimeExceeded) {
			id, seq, ok := extractEmbeddedEchoIDSeq(body.Data, isIPv4)
			return id, seq, false, ok
		}
	case *icmp.DstUnreach:
		if (isIPv4 && rm.Type == ipv4.ICMPTypeDestinationUnreachable) || (!isIPv4 && rm.Type == ipv6.ICMPTypeDestinationUnreachable) {
			id, seq, ok := extractEmbeddedEchoIDSeq(body.Data, isIPv4)
			return id, seq, peerIP == targetStr, ok
		}
	}
	return 0, 0, false, false
}

func matchICMPMTRReply(rm *icmp.Message, isIPv4 bool, probeID, seq int, peerIP, targetIP string) (bool, bool) {
	id, embeddedSeq, reached, valid := extractICMPWaveReply(rm, isIPv4, peerIP, targetIP)
	if !valid || id != probeID || embeddedSeq != seq {
		return false, false
	}
	if rm.Type == ipv4.ICMPTypeEchoReply || rm.Type == ipv6.ICMPTypeEchoReply {
		return true, true
	}
	return true, reached
}

func extractEmbeddedEchoIDSeq(data []byte, isIPv4 bool) (int, int, bool) {
	if isIPv4 {
		if len(data) < ipv4HeaderLen {
			return 0, 0, false
		}
		ihl := int(data[0]&0x0f) * 4
		if ihl < ipv4HeaderLen || len(data) < ihl+l4HeaderLen || data[9] != mtrICMPProtoV4 {
			return 0, 0, false
		}
		return int(binary.BigEndian.Uint16(data[ihl+4 : ihl+6])), int(binary.BigEndian.Uint16(data[ihl+6 : ihl+8])), true
	}
	if len(data) < ipv6HeaderLen+l4HeaderLen || data[6] != mtrICMPProtoV6 {
		return 0, 0, false
	}
	return int(binary.BigEndian.Uint16(data[ipv6HeaderLen+4 : ipv6HeaderLen+6])),
		int(binary.BigEndian.Uint16(data[ipv6HeaderLen+6 : ipv6HeaderLen+8])), true
}
