package dispatch

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
	"github.com/FrankXLT/mcp-adv-netutils/internal/cronmon"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
)

type jobPayloadEnvelope struct {
	Raw            json.RawMessage    `json:"raw,omitempty"`
	ASCII          map[string]string  `json:"ascii,omitempty"`
	ElapsedMS      float64            `json:"elapsed_ms,omitempty"`
	Whiskers       []WhiskerPoint     `json:"whiskers,omitempty"`
	Waterfall      []WaterfallPhase   `json:"waterfall,omitempty"`
	LANInventory   *LANInventoryView  `json:"lan_inventory,omitempty"`
	SnapshotDiff   *SnapshotDiffView  `json:"snapshot_diff,omitempty"`
	TLSHealth      *TLSHealthView     `json:"tls_health,omitempty"`
	DNSComparisons []DNSComparisonRow `json:"dns_comparisons,omitempty"`
}

type lockedCronSummary struct {
	Tool         string   `json:"tool"`
	Period       string   `json:"period"`
	Status       string   `json:"status"`
	Locked       bool     `json:"locked"`
	ChecksTotal  int      `json:"checks_total"`
	AlertsActive int      `json:"alerts_active"`
	PendingWarn  int      `json:"pending_warn"`
	HealthStrip  string   `json:"health_strip"`
	HealthStates []string `json:"health_states,omitempty"`
}

type jobFallbackRaw struct {
	JobID      string  `json:"job_id"`
	Tool       string  `json:"tool"`
	Target     string  `json:"target"`
	Status     string  `json:"status"`
	Summary    string  `json:"summary"`
	CreatedAt  string  `json:"created_at,omitempty"`
	ExpiresAt  string  `json:"expires_at,omitempty"`
	DurationMS int64   `json:"duration_ms"`
	ElapsedMS  float64 `json:"elapsed_ms,omitempty"`
	DownAged   bool    `json:"down_aged,omitempty"`
}

type cardSpec struct {
	tool, title, subtitle, target, status, summary string
	durMS                                          int64
	raw                                            any
	metrics                                        []ascii.MetricKV
	headers                                        []string
	rows                                           []ascii.TableRow
	spark                                          []float64
	health, notes                                  []string
	whiskers                                       []WhiskerPoint
	waterfall                                      []WaterfallPhase
	lan                                            *LANInventoryView
	diff                                           *SnapshotDiffView
	tlsHealth                                      *TLSHealthView
	dnsComparisons                                 []DNSComparisonRow
	deadbolt                                       *security.DeadboltStatus
}

const (
	statusOK           = "OK"
	statusWARN         = "WARN"
	statusFAIL         = "FAIL"
	statusINFO         = "INFO"
	lockedStripWidth   = 24
	retentionDaysLabel = "30d"
)

func makeExecCard(s *cardSpec) *toolExec {
	card := &ascii.ReportCard{
		Title: s.title, Subtitle: s.subtitle, ToolName: s.tool, Target: s.target,
		Status: firstNonEmpty(s.status, statusOK), DurationMS: s.durMS, Summary: s.summary,
		Metrics: s.metrics, Headers: s.headers, Rows: s.rows, SparkValues: s.spark,
		HealthStates: s.health, Notes: s.notes, RawJSON: s.raw,
	}
	return &toolExec{
		Target: s.target, Status: card.Status, Summary: s.summary, Data: s.raw, Card: card,
		Whiskers: s.whiskers, Waterfall: s.waterfall, LANInventory: s.lan, SnapshotDiff: s.diff,
		TLSHealth: s.tlsHealth, DNSComparisons: s.dnsComparisons, Deadbolt: s.deadbolt,
	}
}

func measureDuration(started time.Time) (int64, float64) {
	if started.IsZero() {
		return 0, 0
	}
	elapsed := time.Since(started)
	elapsedMS := math.Round(float64(elapsed.Microseconds())/10.0) / 100.0
	if elapsed > 0 && elapsedMS < 0.01 {
		elapsedMS = 0.01
	}
	durMS := elapsed.Milliseconds()
	if elapsed > 0 && durMS == 0 {
		durMS = 1
	}
	return durMS, elapsedMS
}

func finalizeOutcome(tool, normStyle string, execRes *toolExec, now time.Time, durMS int64, elapsedMS float64, jobID string, expiresAt time.Time) (*Outcome, error) {
	card := execRes.Card
	if card == nil {
		card = &ascii.ReportCard{Title: strings.ToUpper(tool), ToolName: tool, Target: execRes.Target, Status: execRes.Status, Summary: execRes.Summary, RawJSON: execRes.Data}
	}
	if durMS <= 0 && card.DurationMS > 0 {
		durMS = card.DurationMS
	}
	if elapsedMS <= 0 && durMS > 0 {
		elapsedMS = float64(durMS)
	}
	card.ToolName, card.Target = tool, firstNonEmpty(card.Target, execRes.Target)
	card.Status, card.Summary = firstNonEmpty(card.Status, execRes.Status, statusOK), firstNonEmpty(card.Summary, execRes.Summary)
	card.DurationMS = durMS
	if card.RawJSON == nil && execRes.Data != nil {
		card.RawJSON = execRes.Data
	}
	expiresStr := ""
	if jobID != "" {
		card.JobID = jobID
	}
	if !expiresAt.IsZero() {
		card.ExpiresIn = retentionDaysLabel
		expiresStr = expiresAt.UTC().Format(time.RFC3339)
	}
	asciiMap, output, err := renderAllCardStyles(card, normStyle)
	if err != nil {
		return nil, err
	}
	return &Outcome{
		JobID: jobID, Tool: tool, Target: firstNonEmpty(execRes.Target, card.Target), Status: card.Status,
		Summary: card.Summary, CreatedAt: now.UTC().Format(time.RFC3339), ExpiresAt: expiresStr, DurationMS: durMS, ElapsedMS: elapsedMS,
		Style: normStyle, Output: output, ASCII: asciiMap, Data: execRes.Data, Whiskers: execRes.Whiskers,
		Waterfall: execRes.Waterfall, LANInventory: execRes.LANInventory, SnapshotDiff: execRes.SnapshotDiff,
		TLSHealth: execRes.TLSHealth, DNSComparisons: execRes.DNSComparisons, Deadbolt: execRes.Deadbolt,
	}, nil
}

func renderAllCardStyles(card *ascii.ReportCard, normStyle string) (map[string]string, string, error) {
	styles := []string{ascii.StyleDefault, ascii.StyleQuick, ascii.StyleRich}
	asciiMap := make(map[string]string, len(styles))
	for _, st := range styles {
		rendered, err := ascii.Render(card, st)
		if err != nil {
			return nil, "", fmt.Errorf("render %s style: %w", st, err)
		}
		asciiMap[st] = rendered
	}
	if normStyle == ascii.StyleJSON {
		jsonOut, err := ascii.Render(card, ascii.StyleJSON)
		if err != nil {
			return nil, "", fmt.Errorf("render json style: %w", err)
		}
		return asciiMap, jsonOut, nil
	}
	return asciiMap, asciiMap[normStyle], nil
}

func encodePayloadEnvelope(out *Outcome) (string, error) {
	var rawMsg json.RawMessage
	if out.Data != nil {
		rawBytes, err := json.Marshal(out.Data)
		if err != nil {
			return "", fmt.Errorf("marshal job raw payload: %w", err)
		}
		rawMsg = rawBytes
	}
	data, err := json.Marshal(jobPayloadEnvelope{
		Raw: rawMsg, ASCII: out.ASCII, ElapsedMS: out.ElapsedMS, Whiskers: out.Whiskers, Waterfall: out.Waterfall,
		LANInventory: out.LANInventory, SnapshotDiff: out.SnapshotDiff,
		TLSHealth: out.TLSHealth, DNSComparisons: out.DNSComparisons,
	})
	if err != nil {
		return "", fmt.Errorf("marshal job payload envelope: %w", err)
	}
	return string(data), nil
}

func outcomeFromJobRecord(rec *store.JobRecord, normStyle string) (*Outcome, error) {
	var env jobPayloadEnvelope
	var rawData any
	if strings.TrimSpace(rec.PayloadJSON) != "" {
		if err := json.Unmarshal([]byte(rec.PayloadJSON), &env); err == nil && hasEnvelopeContent(&env) {
			if len(env.Raw) > 0 && string(env.Raw) != "null" {
				_ = json.Unmarshal(env.Raw, &rawData)
			}
		} else {
			_ = json.Unmarshal([]byte(rec.PayloadJSON), &rawData)
		}
	}
	elapsedMS := env.ElapsedMS
	if elapsedMS <= 0 && rec.DurationMS > 0 {
		elapsedMS = float64(rec.DurationMS)
	}
	createdStr, expiresStr := formatUnixTime(rec.CreatedAt), formatUnixTime(rec.ExpiresAt)
	if rawData == nil {
		rawData = jobFallbackRaw{
			JobID: rec.JobID, Tool: rec.ToolName, Target: rec.Target, Status: rec.Status, Summary: rec.Summary,
			CreatedAt: createdStr, ExpiresAt: expiresStr, DurationMS: rec.DurationMS, ElapsedMS: elapsedMS, DownAged: rec.DownAged,
		}
	}
	var notes []string
	if rec.DownAged || strings.TrimSpace(rec.PayloadJSON) == "" {
		notes = append(notes, "Compact archive fallback: full payload omitted or down-aged.")
	}
	fallbackCard := &ascii.ReportCard{
		Title: strings.ToUpper(rec.ToolName), ToolName: rec.ToolName, Target: rec.Target, Status: rec.Status,
		JobID: rec.JobID, ExpiresIn: formatRemainingLabel(rec.ExpiresAt), DurationMS: rec.DurationMS,
		Summary: rec.Summary, Notes: notes, RawJSON: rawData,
	}
	asciiMap, err := hydrateASCIIFromRecord(rec, &env, fallbackCard)
	if err != nil {
		return nil, err
	}
	output := asciiMap[normStyle]
	if normStyle == ascii.StyleJSON {
		if output, err = ascii.Render(fallbackCard, ascii.StyleJSON); err != nil {
			return nil, fmt.Errorf("render archived job json: %w", err)
		}
	}
	return &Outcome{
		JobID: rec.JobID, Tool: rec.ToolName, Target: rec.Target, Status: rec.Status, Summary: rec.Summary,
		CreatedAt: createdStr, ExpiresAt: expiresStr, DurationMS: rec.DurationMS, ElapsedMS: elapsedMS, Style: normStyle,
		Output: output, ASCII: asciiMap, Data: rawData, Whiskers: env.Whiskers, Waterfall: env.Waterfall,
		LANInventory: env.LANInventory, SnapshotDiff: env.SnapshotDiff,
		TLSHealth: env.TLSHealth, DNSComparisons: env.DNSComparisons,
	}, nil
}

func hydrateASCIIFromRecord(rec *store.JobRecord, env *jobPayloadEnvelope, card *ascii.ReportCard) (map[string]string, error) {
	out := make(map[string]string, 3)
	for k, v := range env.ASCII {
		if v != "" {
			out[k] = v
		}
	}
	if out[ascii.StyleDefault] == "" && rec.ASCIIDefault != "" {
		out[ascii.StyleDefault] = rec.ASCIIDefault
	}
	for _, st := range []string{ascii.StyleDefault, ascii.StyleQuick, ascii.StyleRich} {
		if out[st] == "" {
			rendered, err := ascii.Render(card, st)
			if err != nil {
				return nil, fmt.Errorf("render fallback %s style: %w", st, err)
			}
			out[st] = rendered
		}
	}
	return out, nil
}

func hasEnvelopeContent(env *jobPayloadEnvelope) bool {
	return len(env.Raw) > 0 || len(env.ASCII) > 0 || env.ElapsedMS > 0 || len(env.Whiskers) > 0 ||
		len(env.Waterfall) > 0 || env.LANInventory != nil || env.SnapshotDiff != nil ||
		env.TLSHealth != nil || len(env.DNSComparisons) > 0
}

func buildLockedCronSummaryExec(summary *store.CronSummary, durMS int64, st *security.DeadboltStatus) *toolExec {
	if st == nil {
		st = &security.DeadboltStatus{}
	}
	checksTotal, alertsActive, pendingWarn, period := 0, 0, 0, "24h"
	if summary != nil {
		period, checksTotal = firstNonEmpty(summary.Period, "24h"), len(summary.States)
		for i := range summary.States {
			if summary.States[i].ActiveAlert {
				alertsActive++
			} else if summary.States[i].ConsecutiveNonOK > 0 {
				pendingWarn++
			}
		}
	}
	healthStates := buildDailyHealthStates(summary)
	overall := overallAlertStatus(alertsActive, pendingWarn)
	strip := ascii.HealthStrip(healthStates, lockedStripWidth)
	msg := fmt.Sprintf("Locked summary (%s): checks_total=%d alerts_active=%d pending_warn=%d", period, checksTotal, alertsActive, pendingWarn)
	payload := lockedCronSummary{
		Tool: "get_cron_status", Period: period, Status: overall, Locked: true, ChecksTotal: checksTotal,
		AlertsActive: alertsActive, PendingWarn: pendingWarn, HealthStrip: strip, HealthStates: healthStates,
	}
	return makeExecCard(&cardSpec{
		tool: "get_cron_status", title: "CRON STATUS (LOCKED)", subtitle: period, status: overall, durMS: durMS, summary: msg,
		raw: payload, health: healthStates, deadbolt: st,
		metrics: []ascii.MetricKV{
			{Label: "checks_total", Value: strconv.Itoa(checksTotal)},
			{Label: "alerts_active", Value: strconv.Itoa(alertsActive)},
			{Label: "pending_warn", Value: strconv.Itoa(pendingWarn)},
			{Label: "HealthStrip", Value: strip},
		},
		notes: []string{"Deadbolt locked: targets, hostnames, IPs, job keys, and summaries redacted."},
	})
}

func buildDailyHealthStates(summary *store.CronSummary) []string {
	if summary == nil {
		return nil
	}
	byDay := make(map[string]string)
	for i := range summary.DailyStats {
		d := &summary.DailyStats[i]
		cur := byDay[d.DayUTC]
		switch {
		case d.FailCount > 0:
			byDay[d.DayUTC] = statusFAIL
		case d.WarnCount > 0 && cur != statusFAIL:
			byDay[d.DayUTC] = statusWARN
		case cur == "":
			byDay[d.DayUTC] = statusOK
		}
	}
	if len(byDay) > 0 {
		days := make([]string, 0, len(byDay))
		for day := range byDay {
			days = append(days, day)
		}
		sort.Strings(days)
		out := make([]string, 0, len(days))
		for _, day := range days {
			out = append(out, byDay[day])
		}
		return out
	}
	out := make([]string, 0, len(summary.States))
	for i := range summary.States {
		st := &summary.States[i]
		switch {
		case st.ActiveAlert:
			out = append(out, statusFAIL)
		case st.ConsecutiveNonOK > 0 || !strings.EqualFold(st.LastStatus, statusOK):
			out = append(out, statusWARN)
		default:
			out = append(out, statusOK)
		}
	}
	return out
}

func buildCronStatusExec(summary *store.CronSummary, card *ascii.ReportCard, durMS int64) *toolExec {
	if card != nil {
		if card.RawJSON == nil {
			card.RawJSON = summary
		}
		return &toolExec{Target: card.Subtitle, Status: firstNonEmpty(card.Status, statusOK), Summary: card.Summary, Data: summary, Card: card}
	}
	checksTotal, alertsActive, pendingWarn, period := 0, 0, 0, "24h"
	var rows []ascii.TableRow
	if summary != nil {
		period, checksTotal = summary.Period, len(summary.States)
		rows = make([]ascii.TableRow, 0, checksTotal)
		for i := range summary.States {
			st := &summary.States[i]
			rStat, badge := statusOK, "0/2 clear"
			if st.ActiveAlert {
				rStat, badge = statusFAIL, strconv.Itoa(st.ConsecutiveNonOK)+"/2 alert"
				alertsActive++
			} else if st.ConsecutiveNonOK > 0 {
				rStat, badge = statusWARN, strconv.Itoa(st.ConsecutiveNonOK)+"/2 warn"
				pendingWarn++
			}
			rows = append(rows, ascii.TableRow{Status: rStat, Cells: []string{st.JobKey, st.ToolName, st.Target, badge, st.LastSummary}})
		}
	}
	overall := overallAlertStatus(alertsActive, pendingWarn)
	return makeExecCard(&cardSpec{
		tool: "get_cron_status", title: "CRON WATCHLIST", subtitle: period, target: period, status: overall, durMS: durMS,
		summary: fmt.Sprintf("%d checks (%s): %d active alert(s), %d pending.", checksTotal, period, alertsActive, pendingWarn),
		raw:     summary, health: buildDailyHealthStates(summary),
		metrics: []ascii.MetricKV{{Label: "Checks", Value: strconv.Itoa(checksTotal)}, {Label: "Alerts", Value: strconv.Itoa(alertsActive)}, {Label: "Pending", Value: strconv.Itoa(pendingWarn)}},
		headers: []string{"KEY", "TOOL", "TARGET", "HYST", "DETAIL"}, rows: ascii.SortRowsBySeverity(rows),
	})
}

func buildManageWatchlistExec(res *cronmon.ManageResult, durMS int64) *toolExec {
	rows := make([]ascii.TableRow, 0, len(res.Items))
	for i := range res.Items {
		it := &res.Items[i]
		st, stateTxt := statusOK, "enabled"
		if !it.Enabled {
			st, stateTxt = statusWARN, "paused"
		}
		rows = append(rows, ascii.TableRow{Status: st, Cells: []string{it.Key, it.Schedule, it.Tool, it.Target, stateTxt}})
	}
	target := ""
	if res.Item != nil {
		target = res.Item.Key
	}
	summary := fmt.Sprintf("Watchlist action %q: %d item(s)", res.Action, len(res.Items))
	if res.Tick != nil {
		summary = fmt.Sprintf("Watchlist %s %q -> %s (%s)", res.Action, target, res.Tick.LastStatus, res.Tick.LastSummary)
	}
	return makeExecCard(&cardSpec{
		tool: "manage_cron_watchlist", title: "CRON WATCHLIST MANAGER", subtitle: res.Action, target: target, status: statusOK, durMS: durMS,
		summary: summary, raw: res, metrics: []ascii.MetricKV{{Label: "Action", Value: res.Action}, {Label: "Items", Value: strconv.Itoa(len(res.Items))}},
		headers: []string{"Key", "Schedule", "Tool", "Target", "State"}, rows: rows,
	})
}

func buildDeadboltExec(toolName, status, summary string, st *security.DeadboltStatus, durMS int64) *toolExec {
	if st == nil {
		st = &security.DeadboltStatus{}
	}
	stateStr := "LOCKED"
	if !st.Enabled {
		stateStr = "DISABLED"
	} else if st.Unlocked {
		stateStr = "UNLOCKED"
	}
	return makeExecCard(&cardSpec{
		tool: toolName, title: "DEADBOLT SECURITY", subtitle: stateStr, status: status, durMS: durMS, summary: summary, raw: st, deadbolt: st,
		metrics: []ascii.MetricKV{
			{Label: "Enabled", Value: strconv.FormatBool(st.Enabled)},
			{Label: "Unlocked", Value: strconv.FormatBool(st.Unlocked)},
			{Label: "TTL(s)", Value: strconv.FormatInt(st.TTLSeconds, 10)},
			{Label: "Remaining(s)", Value: strconv.FormatInt(st.RemainingSeconds, 10)},
		},
		headers: []string{"Attribute", "Value"},
		rows: []ascii.TableRow{
			{Status: status, Cells: []string{"State", stateStr}},
			{Status: statusINFO, Cells: []string{"Failed Attempts", strconv.Itoa(st.FailedAttempts)}},
			{Status: statusINFO, Cells: []string{"Locked Out", strconv.FormatBool(st.LockedOut)}},
		},
	})
}

func overallAlertStatus(alertsActive, pendingWarn int) string {
	if alertsActive > 0 {
		return statusFAIL
	}
	if pendingWarn > 0 {
		return statusWARN
	}
	return statusOK
}

func worstStatusVal(a, b string) string {
	if a == statusFAIL || b == statusFAIL {
		return statusFAIL
	}
	if a == statusWARN || b == statusWARN {
		return statusWARN
	}
	return statusOK
}

func formatUnixTime(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

func formatRemainingLabel(expiresUnix int64) string {
	if expiresUnix <= 0 {
		return ""
	}
	rem := time.Until(time.Unix(expiresUnix, 0).UTC())
	if rem <= 0 {
		return "expired"
	}
	if days := int(rem.Hours() / 24); days > 0 {
		return strconv.Itoa(days) + "d"
	}
	return strconv.Itoa(max(int(rem.Hours()), 1)) + "h"
}
