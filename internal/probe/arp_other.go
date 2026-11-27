//go:build !linux

package probe

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
)

func collectARPEntries(ctx context.Context, _ *net.IPNet, _ string, _ bool, timeout time.Duration, _ *security.TargetGuard) ([]rawARPEntry, string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out, err := exec.CommandContext(cmdCtx, "arp", "-a").Output()
	if err != nil {
		return nil, "unsupported", nil
	}

	entries := parseARPCommandOutput(out)
	return entries, "arp_command", nil
}

func parseARPCommandOutput(raw []byte) []rawARPEntry {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	var entries []rawARPEntry

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if entry, ok := parseBSDARPLine(line); ok {
			entries = append(entries, entry)
			continue
		}
		if entry, ok := parseWindowsARPLine(line); ok {
			entries = append(entries, entry)
		}
	}

	return entries
}

func parseBSDARPLine(line string) (rawARPEntry, bool) {
	openParen := strings.IndexByte(line, '(')
	closeParen := strings.IndexByte(line, ')')
	if openParen < 0 || closeParen <= openParen+1 {
		return rawARPEntry{}, false
	}

	ip := net.ParseIP(strings.TrimSpace(line[openParen+1 : closeParen]))
	if ip == nil || ip.To4() == nil {
		return rawARPEntry{}, false
	}

	rest := line[closeParen+1:]
	_, afterAt, hasAt := strings.Cut(rest, " at ")
	if !hasAt {
		return rawARPEntry{}, false
	}

	fields := strings.Fields(afterAt)
	if len(fields) == 0 || isIncompleteMAC(fields[0]) {
		return rawARPEntry{}, false
	}

	iface := ""
	for i := 1; i+1 < len(fields); i++ {
		if fields[i] == "on" {
			iface = fields[i+1]
			break
		}
	}

	return rawARPEntry{
		ip:    ip.To4(),
		mac:   fields[0],
		iface: iface,
		state: "complete",
	}, true
}

func parseWindowsARPLine(line string) (rawARPEntry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return rawARPEntry{}, false
	}

	ip := net.ParseIP(fields[0])
	if ip == nil || ip.To4() == nil {
		return rawARPEntry{}, false
	}

	mac := fields[1]
	if isIncompleteMAC(mac) {
		return rawARPEntry{}, false
	}

	return rawARPEntry{
		ip:    ip.To4(),
		mac:   mac,
		state: strings.ToLower(fields[2]),
	}, true
}
