package probe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/dns"
	"github.com/FrankXLT/mcp-adv-netutils/internal/mac_lookup"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
)

// ARPSweepParams defines parameters for ARP table inspection and bounded active ARP sweeping.
type ARPSweepParams struct {
	CIDR        string `json:"cidr,omitempty"`
	Interface   string `json:"interface,omitempty"`
	ActiveProbe bool   `json:"active_probe,omitempty"`
	ResolvePTR  bool   `json:"resolve_ptr,omitempty"`
	TimeoutMS   int    `json:"timeout_ms,omitempty"`
}

// ARPNeighbor represents a discovered neighbor with OUI vendor and UAA/LAA classification.
type ARPNeighbor struct {
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	Vendor      string `json:"vendor"`
	AddressType string `json:"address_type"`
	Group       string `json:"group"`
	Hostname    string `json:"hostname,omitempty"`
	Interface   string `json:"interface,omitempty"`
	State       string `json:"state,omitempty"`
	IsLAA       bool   `json:"is_laa"`
}

// ARPSweepResult summarizes discovered ARP neighbors grouped by physical UAA vs virtual LAA.
type ARPSweepResult struct {
	CIDR          string        `json:"cidr,omitempty"`
	ProbeMode     string        `json:"probe_mode"`
	TotalCount    int           `json:"total_count"`
	PhysicalCount int           `json:"physical_count"`
	VirtualCount  int           `json:"virtual_count"`
	Neighbors     []ARPNeighbor `json:"neighbors"`
	Timestamp     string        `json:"timestamp"`
}

type rawARPEntry struct {
	ip        net.IP
	mac       string
	iface     string
	state     string
	fromProbe bool
}

const (
	arpGroupPhysicalUAA = "PHYSICAL - UAA"
	arpGroupVirtualLAA  = "DOCKER/VM - LAA"

	minARPSweepPrefix = 22
	defaultARPTimeout = 2000 * time.Millisecond
	minARPTimeoutMS   = 200
	maxARPTimeoutMS   = 10000
	incompleteMAC     = "00:00:00:00:00:00"
)

var (
	errARPCIDRTooBroad = errors.New("CIDR prefix is too broad for ARP sweep")
	errARPIPv4Required = errors.New("ARP sweep only supports IPv4 CIDRs")
)

// ExecuteARPSweep inspects the local ARP table or performs a bounded active ARP sweep,
// enriches MAC addresses via IEEE OUI lookup, classifies UAA vs LAA entries, and
// optionally resolves PTR hostnames in batches of up to 256 IPs.
func ExecuteARPSweep(ctx context.Context, params ARPSweepParams, guard *security.TargetGuard, dnsCfg *dns.QueryConfig) (*ARPSweepResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", security.ErrTargetInvalid)
	}

	ifaceFilter, err := sanitizeInterfaceName(params.Interface)
	if err != nil {
		return nil, err
	}

	targetNet, normalizedCIDR, err := validateARPSweepCIDR(params.CIDR, guard)
	if err != nil {
		return nil, err
	}

	timeout := normalizeARPTimeout(params.TimeoutMS)
	rawEntries, probeMode, err := collectARPEntries(ctx, targetNet, ifaceFilter, params.ActiveProbe, timeout, guard)
	if err != nil {
		return nil, err
	}

	neighbors, physCount, virtCount := buildARPNeighbors(rawEntries, targetNet, ifaceFilter, guard)

	if params.ResolvePTR && len(neighbors) > 0 {
		if ptrErr := enrichARPNeighborsPTR(ctx, neighbors, dnsCfg, timeout); ptrErr != nil {
			return nil, ptrErr
		}
	}

	return &ARPSweepResult{
		CIDR:          normalizedCIDR,
		ProbeMode:     probeMode,
		TotalCount:    len(neighbors),
		PhysicalCount: physCount,
		VirtualCount:  virtCount,
		Neighbors:     neighbors,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func sanitizeInterfaceName(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	clean, err := security.SanitizeTarget(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid interface name: %w", err)
	}
	return clean, nil
}

func validateARPSweepCIDR(rawCIDR string, guard *security.TargetGuard) (*net.IPNet, string, error) {
	trimmed := strings.TrimSpace(rawCIDR)
	if trimmed == "" {
		return nil, "", nil
	}

	_, ipNet, err := guard.ValidateCIDR(trimmed)
	if err != nil {
		return nil, "", fmt.Errorf("CIDR validation failed: %w", err)
	}

	if ipNet.IP.To4() == nil {
		return nil, "", fmt.Errorf("%w: got %s", errARPIPv4Required, ipNet.String())
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones < minARPSweepPrefix {
		return nil, "", fmt.Errorf("%w: /%d exceeds maximum sweep size (minimum prefix /%d)", errARPCIDRTooBroad, ones, minARPSweepPrefix)
	}

	cidrStr := ipNet.String()
	return ipNet, cidrStr, nil
}

func normalizeARPTimeout(timeoutMS int) time.Duration {
	if timeoutMS <= 0 {
		return defaultARPTimeout
	}
	if timeoutMS < minARPTimeoutMS {
		return time.Duration(minARPTimeoutMS) * time.Millisecond
	}
	if timeoutMS > maxARPTimeoutMS {
		return time.Duration(maxARPTimeoutMS) * time.Millisecond
	}
	return time.Duration(timeoutMS) * time.Millisecond
}

func buildARPNeighbors(entries []rawARPEntry, targetNet *net.IPNet, ifaceFilter string, guard *security.TargetGuard) ([]ARPNeighbor, int, int) {
	deduped := deduplicateARPEntries(entries, targetNet, ifaceFilter, guard)
	neighbors := make([]ARPNeighbor, 0, len(deduped))
	physCount := 0
	virtCount := 0

	for i := range deduped {
		entry := &deduped[i]
		neighbor, ok := enrichARPNeighbor(entry)
		if !ok {
			continue
		}
		if neighbor.IsLAA {
			virtCount++
		} else {
			physCount++
		}
		neighbors = append(neighbors, neighbor)
	}

	sort.Slice(neighbors, func(i, j int) bool {
		a, aErr := netip.ParseAddr(neighbors[i].IP)
		b, bErr := netip.ParseAddr(neighbors[j].IP)
		if aErr == nil && bErr == nil {
			if cmp := a.Compare(b); cmp != 0 {
				return cmp < 0
			}
		}
		return neighbors[i].IP < neighbors[j].IP
	})

	return neighbors, physCount, virtCount
}

func deduplicateARPEntries(entries []rawARPEntry, targetNet *net.IPNet, ifaceFilter string, guard *security.TargetGuard) []rawARPEntry {
	byKey := make(map[string]rawARPEntry, len(entries))
	order := make([]string, 0, len(entries))

	for i := range entries {
		entry := entries[i]
		ip4 := entry.ip.To4()
		if ip4 == nil {
			continue
		}
		if guard.ValidateIP(ip4) != nil {
			continue
		}
		if targetNet != nil && !targetNet.Contains(ip4) {
			continue
		}
		if ifaceFilter != "" && entry.iface != "" && !strings.EqualFold(entry.iface, ifaceFilter) {
			continue
		}
		if isIncompleteMAC(entry.mac) {
			continue
		}

		key := ip4.String() + "|" + entry.iface
		existing, exists := byKey[key]
		if !exists {
			order = append(order, key)
			byKey[key] = rawARPEntry{
				ip:        ip4,
				mac:       entry.mac,
				iface:     entry.iface,
				state:     entry.state,
				fromProbe: entry.fromProbe,
			}
			continue
		}
		if entry.fromProbe && !existing.fromProbe {
			byKey[key] = rawARPEntry{
				ip:        ip4,
				mac:       entry.mac,
				iface:     entry.iface,
				state:     entry.state,
				fromProbe: entry.fromProbe,
			}
		}
	}

	out := make([]rawARPEntry, 0, len(order))
	for _, key := range order {
		out = append(out, byKey[key])
	}
	return out
}

func enrichARPNeighbor(entry *rawARPEntry) (ARPNeighbor, bool) {
	lookup, err := mac_lookup.Execute(entry.mac)
	if err != nil {
		return ARPNeighbor{}, false
	}

	group := arpGroupPhysicalUAA
	if lookup.IsLocallyAdministered {
		group = arpGroupVirtualLAA
	}

	return ARPNeighbor{
		IP:          entry.ip.String(),
		MAC:         lookup.NormalizedMAC,
		Vendor:      lookup.Vendor,
		AddressType: lookup.AddressType,
		Group:       group,
		Interface:   entry.iface,
		State:       entry.state,
		IsLAA:       lookup.IsLocallyAdministered,
	}, true
}

func enrichARPNeighborsPTR(ctx context.Context, neighbors []ARPNeighbor, dnsCfg *dns.QueryConfig, timeout time.Duration) error {
	uniqueIPs := make([]string, 0, len(neighbors))
	seen := make(map[string]struct{}, len(neighbors))
	for i := range neighbors {
		ip := neighbors[i].IP
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		uniqueIPs = append(uniqueIPs, ip)
	}

	timeoutMS := int(timeout.Milliseconds())
	resolved := make(map[string]string, len(uniqueIPs))

	for start := 0; start < len(uniqueIPs); start += dns.MaxReverseBatchIPs {
		if ctx.Err() != nil {
			return fmt.Errorf("PTR enrichment canceled: %w", ctx.Err())
		}
		end := start + dns.MaxReverseBatchIPs
		if end > len(uniqueIPs) {
			end = len(uniqueIPs)
		}

		batchResp, err := dns.ExecuteReverseBatch(ctx, dns.ReverseDNSBatchParams{
			IPs:       strings.Join(uniqueIPs[start:end], ","),
			TimeoutMS: &timeoutMS,
		}, dnsCfg)
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("PTR enrichment failed: %w", ctx.Err())
			}
			continue
		}

		for ip, host := range batchResp.Results {
			if host != nil && *host != "" {
				resolved[ip] = *host
			}
		}
	}

	for i := range neighbors {
		if host, ok := resolved[neighbors[i].IP]; ok {
			neighbors[i].Hostname = host
		}
	}

	return nil
}

func parseProcNetARP(r io.Reader) ([]rawARPEntry, error) {
	scanner := bufio.NewScanner(r)
	var entries []rawARPEntry
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if lineNum == 1 && strings.HasPrefix(strings.ToLower(line), "ip address") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		ip := net.ParseIP(fields[0])
		if ip == nil || ip.To4() == nil {
			continue
		}

		mac := strings.TrimSpace(fields[3])
		if isIncompleteMAC(mac) {
			continue
		}

		entries = append(entries, rawARPEntry{
			ip:    ip.To4(),
			mac:   mac,
			state: parseLinuxARPFlags(fields[2]),
			iface: strings.TrimSpace(fields[5]),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read ARP table: %w", err)
	}

	return entries, nil
}

func parseLinuxARPFlags(flags string) string {
	switch strings.ToLower(strings.TrimSpace(flags)) {
	case "0x2":
		return "complete"
	case "0x4":
		return "permanent"
	case "0x6":
		return "complete,permanent"
	case "0x0":
		return "incomplete"
	default:
		return strings.TrimSpace(flags)
	}
}

func isIncompleteMAC(mac string) bool {
	trimmed := strings.TrimSpace(mac)
	if trimmed == "" {
		return true
	}
	normalized := strings.ReplaceAll(strings.ToLower(trimmed), "-", ":")
	return normalized == incompleteMAC || strings.EqualFold(trimmed, "(incomplete)")
}

func enumerateIPv4SweepHosts(ipNet *net.IPNet, guard *security.TargetGuard) []netip.Addr {
	if ipNet == nil {
		return nil
	}
	base4 := ipNet.IP.Mask(ipNet.Mask).To4()
	if base4 == nil {
		return nil
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones < minARPSweepPrefix {
		return nil
	}

	total := uint32(1) << (32 - ones)
	baseAddr := uint32(base4[0])<<24 | uint32(base4[1])<<16 | uint32(base4[2])<<8 | uint32(base4[3])

	startOffset := uint32(0)
	endOffset := total
	if ones <= 30 && total > 2 {
		startOffset = 1
		endOffset = total - 1
	}

	hosts := make([]netip.Addr, 0, endOffset-startOffset)
	for offset := startOffset; offset < endOffset; offset++ {
		val := baseAddr + offset
		octets := [4]byte{
			byte((val >> 24) & 0xff),
			byte((val >> 16) & 0xff),
			byte((val >> 8) & 0xff),
			byte(val & 0xff),
		}
		ip := net.IPv4(octets[0], octets[1], octets[2], octets[3])
		if guard.ValidateIP(ip) != nil {
			continue
		}
		hosts = append(hosts, netip.AddrFrom4(octets))
	}

	return hosts
}
