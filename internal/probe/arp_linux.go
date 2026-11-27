//go:build linux

package probe

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/mdlayher/arp"
)

const procNetARPPath = "/proc/net/arp"

func collectARPEntries(ctx context.Context, targetNet *net.IPNet, ifaceFilter string, activeProbe bool, timeout time.Duration, guard *security.TargetGuard) ([]rawARPEntry, string, error) {
	procEntries, procErr := readProcNetARP()

	if activeProbe && targetNet != nil {
		probedEntries, probeErr := runActiveARPProbe(ctx, targetNet, ifaceFilter, timeout, guard)
		if probeErr == nil {
			combined := make([]rawARPEntry, 0, len(probedEntries)+len(procEntries))
			combined = append(combined, probedEntries...)
			combined = append(combined, procEntries...)
			return combined, "active_arp", nil
		}
		if procErr == nil {
			return procEntries, "proc_net_arp_fallback", nil
		}
		return nil, "", fmt.Errorf("active ARP probe failed (%w) and ARP table read failed: %w", probeErr, procErr)
	}

	if procErr != nil {
		return nil, "", procErr
	}
	return procEntries, "proc_net_arp", nil
}

func readProcNetARP() ([]rawARPEntry, error) {
	f, err := os.Open(procNetARPPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", procNetARPPath, err)
	}
	defer func() { _ = f.Close() }()

	entries, err := parseProcNetARP(f)
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func runActiveARPProbe(ctx context.Context, targetNet *net.IPNet, ifaceFilter string, timeout time.Duration, guard *security.TargetGuard) ([]rawARPEntry, error) {
	ifi, err := selectARPInterface(ifaceFilter, targetNet)
	if err != nil {
		return nil, err
	}

	hosts := enumerateIPv4SweepHosts(targetNet, guard)
	if len(hosts) == 0 {
		return nil, nil
	}

	client, err := arp.Dial(ifi)
	if err != nil {
		return nil, fmt.Errorf("failed to open ARP socket on %s: %w", ifi.Name, err)
	}

	deadline := time.Now().Add(timeout)
	_ = client.SetDeadline(deadline)

	var mu sync.Mutex
	replies := make(map[netip.Addr]net.HardwareAddr)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			pkt, _, readErr := client.Read()
			if readErr != nil {
				return
			}
			if pkt == nil || pkt.Operation != arp.OperationReply || !pkt.SenderIP.Is4() {
				continue
			}
			if len(pkt.SenderHardwareAddr) == 0 {
				continue
			}
			hwCopy := make(net.HardwareAddr, len(pkt.SenderHardwareAddr))
			copy(hwCopy, pkt.SenderHardwareAddr)
			mu.Lock()
			replies[pkt.SenderIP] = hwCopy
			mu.Unlock()
		}
	}()

	for _, addr := range hosts {
		if ctx.Err() != nil {
			break
		}
		if reqErr := client.Request(addr); reqErr != nil {
			break
		}
	}

	waitDuration := min(timeout/2, 500*time.Millisecond)
	if waitDuration < 100*time.Millisecond {
		waitDuration = 100 * time.Millisecond
	}
	timer := time.NewTimer(waitDuration)
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
	timer.Stop()

	_ = client.Close()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	entries := make([]rawARPEntry, 0, len(replies))
	for addr, hw := range replies {
		entries = append(entries, rawARPEntry{
			ip:        net.IP(addr.AsSlice()),
			mac:       hw.String(),
			iface:     ifi.Name,
			state:     "reachable",
			fromProbe: true,
		})
	}
	return entries, nil
}

func selectARPInterface(ifaceFilter string, targetNet *net.IPNet) (*net.Interface, error) {
	if ifaceFilter != "" {
		ifi, err := net.InterfaceByName(ifaceFilter)
		if err != nil {
			return nil, fmt.Errorf("interface %q not found: %w", ifaceFilter, err)
		}
		return ifi, nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	for i := range ifaces {
		ifi := &ifaces[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if interfaceMatchesCIDR(ifi, targetNet) {
			return ifi, nil
		}
	}

	return nil, fmt.Errorf("no active non-loopback interface matches %s", targetNet.String())
}

func interfaceMatchesCIDR(ifi *net.Interface, targetNet *net.IPNet) bool {
	addrs, err := ifi.Addrs()
	if err != nil {
		return false
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			continue
		}
		if targetNet.Contains(ip4) || ipNet.Contains(targetNet.IP) {
			return true
		}
	}
	return false
}
