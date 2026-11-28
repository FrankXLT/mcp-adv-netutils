package recipes

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
)

var digestWindowDurations = map[string]time.Duration{"1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}

type parsedDigestFilter struct {
	jobIDs                           []string
	window, target, toolName, status string
	sinceUnix, untilUnix             int64
	sinceISO, untilISO               string
	incidentsOnly                    bool
	limit                            int
}

func parseDigestWindowAndBounds(params *RenderDigestParams, now time.Time) (parsedDigestFilter, error) {
	limit := min(max(params.Limit, 0), maxDigestLimit)
	if params.Limit <= 0 {
		limit = defaultDigestLimit
	}
	out := parsedDigestFilter{target: strings.TrimSpace(params.Target), toolName: strings.TrimSpace(params.ToolName), incidentsOnly: params.IncidentsOnly, limit: limit}
	for _, rawID := range params.JobIDs {
		if id := strings.TrimSpace(rawID); id != "" {
			out.jobIDs = append(out.jobIDs, id)
		}
	}
	rawWin := strings.ToLower(strings.TrimSpace(params.Window))
	if rawWin == "" && len(out.jobIDs) == 0 {
		if _, ok := digestWindowDurations[strings.ToLower(out.target)]; ok {
			rawWin, out.target = strings.ToLower(out.target), ""
		}
	}
	var winDur time.Duration
	if rawWin != "" {
		var ok bool
		if winDur, ok = digestWindowDurations[rawWin]; !ok {
			return out, fmt.Errorf("invalid digest window %q: expected 1h, 6h, 24h, 7d, or 30d", params.Window)
		}
		out.window = rawWin
	}
	var err error
	if out.sinceUnix, err = parseDigestTimestamp(params.Since, "since"); err != nil {
		return out, err
	}
	if out.untilUnix, err = parseDigestTimestamp(params.Until, "until"); err != nil {
		return out, err
	}
	if out.window != "" && strings.TrimSpace(params.Since) == "" {
		out.sinceUnix = now.Add(-winDur).Unix()
	}
	if out.sinceUnix > 0 && out.untilUnix > 0 && out.sinceUnix > out.untilUnix {
		return out, fmt.Errorf("invalid digest time bounds: since (%d) is after until (%d)", out.sinceUnix, out.untilUnix)
	}
	if out.sinceUnix > 0 {
		out.sinceISO = time.Unix(out.sinceUnix, 0).UTC().Format(time.RFC3339)
	}
	if out.untilUnix > 0 {
		out.untilISO = time.Unix(out.untilUnix, 0).UTC().Format(time.RFC3339)
	}
	if rawStatus := strings.ToUpper(strings.TrimSpace(params.Status)); rawStatus != "" {
		if rawStatus != StatusOK && rawStatus != StatusWARN && rawStatus != StatusFAIL {
			return out, fmt.Errorf("invalid digest status %q: expected OK, WARN, or FAIL", params.Status)
		}
		out.status = rawStatus
	}
	return out, nil
}

func parseDigestTimestamp(raw, field string) (int64, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, nil
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts.UTC().Unix(), nil
	}
	if unixSec, err := strconv.ParseInt(s, 10, 64); err == nil && unixSec >= 0 {
		return unixSec, nil
	}
	return 0, fmt.Errorf("invalid digest %s timestamp %q: expected RFC3339 or non-negative Unix seconds", field, raw)
}

func loadDigestJobsAndSummary(ctx context.Context, st *store.JobStore, parsed *parsedDigestFilter) ([]store.JobRecord, *store.JobWindowSummary, error) {
	if len(parsed.jobIDs) > 0 {
		jobs := make([]store.JobRecord, 0, len(parsed.jobIDs))
		for _, id := range parsed.jobIDs {
			rec, err := st.GetJob(ctx, id)
			if err != nil {
				return nil, nil, fmt.Errorf("load job %q: %w", id, err)
			}
			jobs = append(jobs, *rec)
		}
		return jobs, summarizeLoadedJobs(jobs), nil
	}
	filter := store.JobFilter{ToolName: parsed.toolName, TargetContains: parsed.target, Status: parsed.status, Since: parsed.sinceUnix, Until: parsed.untilUnix, IncidentsOnly: parsed.incidentsOnly}
	winSummary, err := st.SummarizeJobs(ctx, filter)
	if err != nil {
		return nil, nil, fmt.Errorf("summarize jobs for digest: %w", err)
	}
	filter.Limit = parsed.limit
	jobs, err := st.ListJobs(ctx, filter)
	if err != nil {
		return nil, nil, fmt.Errorf("list jobs for digest: %w", err)
	}
	return jobs, winSummary, nil
}

func summarizeLoadedJobs(jobs []store.JobRecord) *store.JobWindowSummary {
	if len(jobs) == 0 {
		return nil
	}
	s := &store.JobWindowSummary{TotalMatching: len(jobs), MinDurationMS: jobs[0].DurationMS, MaxDurationMS: jobs[0].DurationMS, EarliestCreatedAt: jobs[0].CreatedAt, LatestCreatedAt: jobs[0].CreatedAt}
	var sumDur int64
	toolMap, toolDurSum, targetMap := make(map[string]*store.ToolDigestCount), make(map[string]int64), make(map[string]*store.TargetProblemCount)
	for i := range jobs {
		j := &jobs[i]
		norm := normalizeRecipeStatus(j.Status)
		sumDur += j.DurationMS
		s.MinDurationMS, s.MaxDurationMS = min(s.MinDurationMS, j.DurationMS), max(s.MaxDurationMS, j.DurationMS)
		s.EarliestCreatedAt, s.LatestCreatedAt = min(s.EarliestCreatedAt, j.CreatedAt), max(s.LatestCreatedAt, j.CreatedAt)
		if j.IsIncident {
			s.IncidentCount++
		}
		td := toolMap[j.ToolName]
		if td == nil {
			td = &store.ToolDigestCount{ToolName: j.ToolName}
			toolMap[j.ToolName] = td
		}
		td.Total++
		toolDurSum[j.ToolName] += j.DurationMS
		var tp *store.TargetProblemCount
		if norm == StatusFAIL || norm == StatusWARN {
			if tp = targetMap[j.Target]; tp == nil {
				tp = &store.TargetProblemCount{Target: j.Target, LastSeenAt: j.CreatedAt}
				targetMap[j.Target] = tp
			}
			tp.TotalNonOK, tp.LastSeenAt = tp.TotalNonOK+1, max(tp.LastSeenAt, j.CreatedAt)
		}
		switch norm {
		case StatusFAIL:
			s.FailCount, td.FailCount, tp.FailCount = s.FailCount+1, td.FailCount+1, tp.FailCount+1
		case StatusWARN:
			s.WarnCount, td.WarnCount, tp.WarnCount = s.WarnCount+1, td.WarnCount+1, tp.WarnCount+1
		default:
			s.OKCount, td.OKCount = s.OKCount+1, td.OKCount+1
		}
	}
	s.AvgDurationMS = float64(sumDur) / float64(len(jobs))
	s.PassRatePct = math.Round(float64(s.OKCount)/float64(len(jobs))*1000) / 10
	s.ToolBreakdown, s.TopProblemTargets = finalizeDigestBreakdowns(toolMap, toolDurSum, targetMap)
	return s
}

func finalizeDigestBreakdowns(toolMap map[string]*store.ToolDigestCount, toolDurSum map[string]int64, targetMap map[string]*store.TargetProblemCount) ([]store.ToolDigestCount, []store.TargetProblemCount) {
	tools, targets := make([]store.ToolDigestCount, 0, len(toolMap)), make([]store.TargetProblemCount, 0, len(targetMap))
	for name, item := range toolMap {
		item.AvgDurationMS = float64(toolDurSum[name]) / float64(item.Total)
		tools = append(tools, *item)
	}
	slices.SortFunc(tools, func(a, b store.ToolDigestCount) int {
		return cmp.Or(cmp.Compare(b.FailCount+b.WarnCount, a.FailCount+a.WarnCount), cmp.Compare(b.Total, a.Total), strings.Compare(a.ToolName, b.ToolName))
	})
	for _, item := range targetMap {
		targets = append(targets, *item)
	}
	slices.SortFunc(targets, func(a, b store.TargetProblemCount) int {
		return cmp.Or(cmp.Compare(b.FailCount, a.FailCount), cmp.Compare(b.WarnCount, a.WarnCount), cmp.Compare(b.LastSeenAt, a.LastSeenAt), strings.Compare(a.Target, b.Target))
	})
	return tools[:min(len(tools), 15)], targets[:min(len(targets), 10)]
}

func buildDigestData(jobs []store.JobRecord, winSummary *store.JobWindowSummary, parsed *parsedDigestFilter) DigestData {
	entries := make([]DigestJobEntry, 0, len(jobs))
	for i := range jobs {
		j := &jobs[i]
		entries = append(entries, DigestJobEntry{JobID: j.JobID, ToolName: j.ToolName, Target: j.Target, Source: j.Source, Status: normalizeRecipeStatus(j.Status), Summary: j.Summary, DurationMS: j.DurationMS, CreatedAt: j.CreatedAt, IsIncident: j.IsIncident})
	}
	slices.SortStableFunc(entries, func(a, b DigestJobEntry) int { return statusSeverityRank(a.Status) - statusSeverityRank(b.Status) })
	var counts digestCounts
	if winSummary != nil {
		counts = digestCounts{winSummary.OKCount, winSummary.WarnCount, winSummary.FailCount, winSummary.IncidentCount}
	}
	data := DigestData{TotalJobs: len(entries), OKCount: counts.ok, WarnCount: counts.warn, FailCount: counts.fail, IncidentCount: counts.incidents, Window: parsed.window, Since: parsed.sinceISO, Until: parsed.untilISO, WindowSummary: winSummary, Jobs: entries, Timestamp: time.Now().UTC().Format(time.RFC3339)}
	capDigestData(&data)
	return data
}

func capDigestData(data *DigestData) {
	const maxDigestJSONBytes, maxDigestSummaryRunes = ascii.MaxJSONBytes - 1024, 160
	if raw, err := json.Marshal(data); err == nil && len(raw) < maxDigestJSONBytes {
		return
	}
	for i := range data.Jobs {
		if utf8.RuneCountInString(data.Jobs[i].Summary) > maxDigestSummaryRunes {
			data.Jobs[i].Summary = string([]rune(data.Jobs[i].Summary)[:maxDigestSummaryRunes-3]) + "..."
		}
	}
	if raw, err := json.Marshal(data); err == nil && len(raw) < maxDigestJSONBytes {
		return
	}
	orig, lo, hi, bestKeep := data.Jobs, 0, len(data.Jobs), 0
	for lo <= hi {
		mid := lo + (hi-lo)/2
		candidate := *data
		candidate.Jobs, candidate.TotalJobs, candidate.Truncated, candidate.OmittedJobs = orig[:mid], mid, true, len(orig)-mid
		if raw, err := json.Marshal(candidate); err == nil && len(raw) < maxDigestJSONBytes {
			bestKeep, lo = mid, mid+1
		} else {
			hi = mid - 1
		}
	}
	kept := make([]DigestJobEntry, bestKeep)
	copy(kept, orig[:bestKeep])
	data.Jobs, data.TotalJobs, data.Truncated, data.OmittedJobs = kept, bestKeep, true, len(orig)-bestKeep
}

func buildDigestCardDecorations(data *DigestData) ([]ascii.MetricKV, []string, string, string) {
	totalMatching, passRate, avgDur, maxDur, overall := data.TotalJobs, 0.0, 0.0, int64(0), StatusOK
	if ws := data.WindowSummary; ws != nil {
		totalMatching, passRate, avgDur, maxDur = ws.TotalMatching, ws.PassRatePct, ws.AvgDurationMS, ws.MaxDurationMS
		if ws.FailCount > 0 {
			overall = StatusFAIL
		} else if ws.WarnCount > 0 {
			overall = StatusWARN
		}
	}
	summary, matchedVal := "No stored jobs matched digest filter", strconv.Itoa(totalMatching)
	if totalMatching > len(data.Jobs) {
		summary = fmt.Sprintf("Matched %d job(s) (showing %d): %d OK, %d WARN, %d FAIL (%d incident(s))", totalMatching, len(data.Jobs), data.OKCount, data.WarnCount, data.FailCount, data.IncidentCount)
		matchedVal = fmt.Sprintf("%d (%d shown)", totalMatching, len(data.Jobs))
	} else if totalMatching > 0 {
		summary = fmt.Sprintf("Consolidated %d job(s): %d OK, %d WARN, %d FAIL (%d incident(s))", totalMatching, data.OKCount, data.WarnCount, data.FailCount, data.IncidentCount)
	}
	metrics := []ascii.MetricKV{
		{Label: "Matched", Value: matchedVal},
		{Label: "Pass Rate", Value: fmt.Sprintf("%.1f%%", passRate)},
		{Label: "OK / WARN / FAIL", Value: fmt.Sprintf("%d / %d / %d", data.OKCount, data.WarnCount, data.FailCount)},
		{Label: "Avg / Max Dur", Value: fmt.Sprintf("%.0fms / %dms", avgDur, maxDur)},
	}
	var notes []string
	if ws := data.WindowSummary; ws != nil {
		if len(ws.TopProblemTargets) > 0 {
			parts := make([]string, 0, min(len(ws.TopProblemTargets), 3))
			for _, t := range ws.TopProblemTargets[:min(len(ws.TopProblemTargets), 3)] {
				parts = append(parts, fmt.Sprintf("%s (%dF/%dW)", t.Target, t.FailCount, t.WarnCount))
			}
			notes = append(notes, "Problem targets: "+strings.Join(parts, ", "))
		}
		if len(ws.ToolBreakdown) > 0 {
			parts := make([]string, 0, min(len(ws.ToolBreakdown), 3))
			for _, t := range ws.ToolBreakdown[:min(len(ws.ToolBreakdown), 3)] {
				tag := "OK"
				if t.FailCount+t.WarnCount > 0 {
					tag = fmt.Sprintf("%dF/%dW", t.FailCount, t.WarnCount)
				}
				parts = append(parts, fmt.Sprintf("%s %d (%s)", t.ToolName, t.Total, tag))
			}
			notes = append(notes, "Tools: "+strings.Join(parts, ", "))
		}
	}
	if data.Truncated {
		notes = append(notes, fmt.Sprintf("JSON capped: omitted %d lower-severity job(s)", data.OmittedJobs))
	}
	return metrics, notes, summary, overall
}
