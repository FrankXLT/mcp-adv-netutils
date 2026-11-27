package probe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/dns"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	miekgdns "github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// SplitDNSParams defines parameters for comparing local resolver vs public DoH DNS answers.
type SplitDNSParams struct {
	Domain      string   `json:"domain"`
	RecordTypes []string `json:"record_types,omitempty"`
}

// SplitDNSComparison records the comparison outcome for a single DNS record type.
type SplitDNSComparison struct {
	RecordType    string   `json:"record_type"`
	Status        string   `json:"status"`
	LocalAnswers  []string `json:"local_answers,omitempty"`
	RemoteAnswers []string `json:"remote_answers,omitempty"`
	LocalTTL      uint32   `json:"local_ttl,omitempty"`
	RemoteTTL     uint32   `json:"remote_ttl,omitempty"`
	LocalErr      string   `json:"local_err,omitempty"`
	RemoteErr     string   `json:"remote_err,omitempty"`
}

// SplitDNSResult summarizes split-horizon DNS differences across queried record types.
type SplitDNSResult struct {
	Domain        string               `json:"domain"`
	OverallStatus string               `json:"overall_status"`
	SplitDetected bool                 `json:"split_detected"`
	Comparisons   []SplitDNSComparison `json:"comparisons"`
	Timestamp     string               `json:"timestamp"`
}

type dnsSideOutcome struct {
	answers []string
	ttl     uint32
	rcode   int
	errMsg  string
}

const (
	splitStatusMatch        = "MATCH"
	splitStatusSplitLocal   = "SPLIT-LOCAL"
	splitStatusLocalOnly    = "LOCAL-ONLY"
	splitStatusPublicOnly   = "PUBLIC-ONLY"
	splitStatusBothNXDomain = "BOTH-NXDOMAIN"
	splitStatusError        = "ERROR"

	maxSplitDNSRecordTypes = 10
	maxSplitDNSConcurrency = 5
)

var defaultSplitDNSRecordTypes = []string{"A", "AAAA", "CNAME", "TXT", "MX"}

// ExecuteSplitDNSAudit queries both local DNS and public DoH resolvers concurrently
// across the requested record types and classifies split-horizon divergences.
func ExecuteSplitDNSAudit(ctx context.Context, params SplitDNSParams, dnsCfg *dns.QueryConfig) (*SplitDNSResult, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}

	domain, err := sanitizeSplitDNSDomain(params.Domain)
	if err != nil {
		return nil, err
	}

	recordTypes, err := normalizeSplitDNSRecordTypes(params.RecordTypes)
	if err != nil {
		return nil, err
	}

	comparisons := make([]SplitDNSComparison, len(recordTypes))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(maxSplitDNSConcurrency)

	for idx, rt := range recordTypes {
		g.Go(func() error {
			comparisons[idx] = auditSplitDNSRecordType(gctx, domain, rt, dnsCfg)
			return nil
		})
	}

	_ = g.Wait()

	overallStatus, splitDetected := summarizeSplitDNS(comparisons)
	return &SplitDNSResult{
		Domain:        domain,
		OverallStatus: overallStatus,
		SplitDetected: splitDetected,
		Comparisons:   comparisons,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func sanitizeSplitDNSDomain(raw string) (string, error) {
	clean, err := security.SanitizeTarget(raw)
	if err != nil {
		return "", fmt.Errorf("invalid domain: %w", err)
	}
	if strings.Contains(clean, "..") || strings.HasPrefix(clean, ".") {
		return "", fmt.Errorf("invalid domain format: %q", clean)
	}
	return strings.TrimSuffix(clean, "."), nil
}

func normalizeSplitDNSRecordTypes(raw []string) ([]string, error) {
	if len(raw) == 0 {
		out := make([]string, len(defaultSplitDNSRecordTypes))
		copy(out, defaultSplitDNSRecordTypes)
		return out, nil
	}

	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		rt := strings.ToUpper(strings.TrimSpace(entry))
		if rt == "" {
			continue
		}
		if _, exists := seen[rt]; exists {
			continue
		}
		if _, err := dns.ConvertToQType(rt); err != nil {
			return nil, fmt.Errorf("invalid record type %q: %w", rt, err)
		}
		seen[rt] = struct{}{}
		out = append(out, rt)
	}

	if len(out) == 0 {
		return nil, errors.New("record_types must contain at least one valid DNS record type")
	}
	if len(out) > maxSplitDNSRecordTypes {
		return nil, fmt.Errorf("too many record types: %d exceeds maximum of %d", len(out), maxSplitDNSRecordTypes)
	}
	return out, nil
}

func auditSplitDNSRecordType(ctx context.Context, domain, recordType string, dnsCfg *dns.QueryConfig) SplitDNSComparison {
	queryParams := dns.DNSQueryParams{
		Domain:     domain,
		RecordType: recordType,
	}

	var localResp *dns.DNSResponse
	var localErr error
	var remoteResp *dns.DNSResponse
	var remoteErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		localResp, localErr = dns.ExecuteLocal(ctx, queryParams, dnsCfg)
	}()
	go func() {
		defer wg.Done()
		remoteResp, remoteErr = dns.ExecuteRemote(ctx, queryParams, dnsCfg)
	}()
	wg.Wait()

	localOutcome := extractDNSSideOutcome(localResp, localErr)
	remoteOutcome := extractDNSSideOutcome(remoteResp, remoteErr)
	status := classifySplitDNSComparison(localOutcome, remoteOutcome)

	return SplitDNSComparison{
		RecordType:    recordType,
		Status:        status,
		LocalAnswers:  localOutcome.answers,
		RemoteAnswers: remoteOutcome.answers,
		LocalTTL:      localOutcome.ttl,
		RemoteTTL:     remoteOutcome.ttl,
		LocalErr:      localOutcome.errMsg,
		RemoteErr:     remoteOutcome.errMsg,
	}
}

func extractDNSSideOutcome(resp *dns.DNSResponse, queryErr error) dnsSideOutcome {
	if queryErr != nil {
		return dnsSideOutcome{errMsg: queryErr.Error()}
	}
	if resp == nil {
		return dnsSideOutcome{errMsg: "empty DNS response"}
	}
	if resp.Status != miekgdns.RcodeSuccess && resp.Status != miekgdns.RcodeNameError {
		return dnsSideOutcome{
			rcode:  resp.Status,
			errMsg: fmt.Sprintf("DNS rcode %d (%s)", resp.Status, resp.StatusMessage),
		}
	}

	answers := make([]string, 0, len(resp.Answer))
	var ttl uint32
	for i := range resp.Answer {
		ans := &resp.Answer[i]
		normalized := normalizeDNSAnswerValue(ans.TypeName, ans.Data)
		if normalized == "" {
			continue
		}
		answers = append(answers, normalized)
		if ttl == 0 || (ans.TTL > 0 && ans.TTL < ttl) {
			ttl = ans.TTL
		}
	}

	slices.Sort(answers)
	answers = slices.Compact(answers)
	if len(answers) == 0 {
		answers = nil
	}

	return dnsSideOutcome{
		answers: answers,
		ttl:     ttl,
		rcode:   resp.Status,
	}
}

func normalizeDNSAnswerValue(typeName, data string) string {
	trimmed := strings.TrimSpace(data)
	if trimmed == "" {
		return ""
	}

	switch strings.ToUpper(strings.TrimSpace(typeName)) {
	case "A", "AAAA":
		if addr, err := netip.ParseAddr(trimmed); err == nil {
			return addr.Unmap().String()
		}
		return strings.ToLower(trimmed)
	case "CNAME", "NS", "PTR":
		return strings.ToLower(strings.TrimSuffix(trimmed, "."))
	case "MX":
		fields := strings.Fields(trimmed)
		if len(fields) == 2 {
			return fields[0] + " " + strings.ToLower(strings.TrimSuffix(fields[1], "."))
		}
		return strings.ToLower(strings.TrimSuffix(trimmed, "."))
	case "SRV":
		fields := strings.Fields(trimmed)
		if len(fields) == 4 {
			return fields[0] + " " + fields[1] + " " + fields[2] + " " + strings.ToLower(strings.TrimSuffix(fields[3], "."))
		}
		return trimmed
	default:
		return trimmed
	}
}

func classifySplitDNSComparison(localSide, remoteSide dnsSideOutcome) string {
	hasLocalErr := localSide.errMsg != ""
	hasRemoteErr := remoteSide.errMsg != ""
	hasLocalAns := len(localSide.answers) > 0
	hasRemoteAns := len(remoteSide.answers) > 0

	switch {
	case hasLocalErr && hasRemoteErr:
		return splitStatusError
	case hasLocalErr && !hasRemoteErr:
		if hasRemoteAns {
			return splitStatusPublicOnly
		}
		return splitStatusError
	case !hasLocalErr && hasRemoteErr:
		if hasLocalAns {
			return splitStatusLocalOnly
		}
		return splitStatusError
	}

	switch {
	case hasLocalAns && hasRemoteAns:
		if slices.Equal(localSide.answers, remoteSide.answers) {
			return splitStatusMatch
		}
		return splitStatusSplitLocal
	case hasLocalAns && !hasRemoteAns:
		return splitStatusLocalOnly
	case !hasLocalAns && hasRemoteAns:
		return splitStatusPublicOnly
	}

	localNX := localSide.rcode == miekgdns.RcodeNameError
	remoteNX := remoteSide.rcode == miekgdns.RcodeNameError
	if localNX && remoteNX {
		return splitStatusBothNXDomain
	}
	if localNX != remoteNX {
		return splitStatusSplitLocal
	}
	return splitStatusMatch
}

func summarizeSplitDNS(comparisons []SplitDNSComparison) (string, bool) {
	splitCount := 0
	matchCount := 0
	nxCount := 0
	errCount := 0

	for i := range comparisons {
		switch comparisons[i].Status {
		case splitStatusSplitLocal, splitStatusLocalOnly, splitStatusPublicOnly:
			splitCount++
		case splitStatusMatch:
			matchCount++
		case splitStatusBothNXDomain:
			nxCount++
		case splitStatusError:
			errCount++
		}
	}

	if splitCount > 0 {
		return "SPLIT-DETECTED", true
	}
	if errCount > 0 && matchCount == 0 && nxCount == 0 {
		return splitStatusError, false
	}
	if errCount > 0 {
		return "PARTIAL-ERROR", false
	}
	if matchCount > 0 {
		return splitStatusMatch, false
	}
	if nxCount > 0 {
		return splitStatusBothNXDomain, false
	}
	return splitStatusMatch, false
}
