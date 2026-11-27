package ascii

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strconv"
	"strings"
)

// MetricKV represents a labeled metric key-value pair displayed in report headers/panels.
type MetricKV struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// TableRow represents a single status-tagged row in a report table.
type TableRow struct {
	Status string   `json:"status"`
	Cells  []string `json:"cells"`
}

// ReportCard is the unified view model rendered across default, quick, rich, and json styles.
type ReportCard struct {
	Title        string     `json:"title,omitempty"`
	Subtitle     string     `json:"subtitle,omitempty"`
	ToolName     string     `json:"tool_name,omitempty"`
	Target       string     `json:"target,omitempty"`
	Status       string     `json:"status,omitempty"`
	JobID        string     `json:"job_id,omitempty"`
	ExpiresIn    string     `json:"expires_in,omitempty"`
	DurationMS   int64      `json:"duration_ms,omitempty"`
	Summary      string     `json:"summary,omitempty"`
	Metrics      []MetricKV `json:"metrics,omitempty"`
	Headers      []string   `json:"headers,omitempty"`
	Rows         []TableRow `json:"rows,omitempty"`
	SparkValues  []float64  `json:"spark_values,omitempty"`
	HealthStates []string   `json:"health_states,omitempty"`
	Notes        []string   `json:"notes,omitempty"`
	RawJSON      any        `json:"-"`
}

type jsonReportPayload struct {
	ReportCard
	Truncated   bool `json:"truncated,omitempty"`
	OmittedRows int  `json:"omitted_rows,omitempty"`
}

const (
	// StyleDefault renders a 72-column exact terminal report card.
	StyleDefault = "default"
	// StyleQuick renders a <=40-column borderless mobile-friendly summary.
	StyleQuick = "quick"
	// StyleRich renders a 76-column boxed TUI report with side-by-side visuals.
	StyleRich = "rich"
	// StyleJSON renders wire-capped JSON strictly under MaxJSONBytes.
	StyleJSON = "json"

	// MaxJSONBytes is the strict wire cap (< 18.5 KB) enforced for JSON output.
	MaxJSONBytes = 18944

	defaultWidth   = 72
	quickWidth     = 40
	richWidth      = 76
	richInnerWidth = 72
)

// NormalizeStyle validates and normalizes a requested render style.
// Empty input defaults to StyleDefault.
func NormalizeStyle(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "":
		return StyleDefault, nil
	case StyleDefault, StyleQuick, StyleRich, StyleJSON:
		return s, nil
	default:
		return "", fmt.Errorf("unsupported ascii style %q: expected default, quick, rich, or json", raw)
	}
}

// SortRowsBySeverity returns a new slice ordered FAIL -> WARN -> OK/INFO/other,
// preserving relative order within each severity bucket.
func SortRowsBySeverity(rows []TableRow) []TableRow {
	if len(rows) == 0 {
		return nil
	}
	out := make([]TableRow, len(rows))
	copy(out, rows)
	sort.SliceStable(out, func(i, j int) bool {
		return severityRank(out[i].Status) < severityRank(out[j].Status)
	})
	return out
}

// Render formats card according to the requested style (default, quick, rich, or json).
func Render(card *ReportCard, style string) (string, error) {
	if card == nil {
		return "", errors.New("report card cannot be nil")
	}
	norm, err := NormalizeStyle(style)
	if err != nil {
		return "", err
	}
	switch norm {
	case StyleJSON:
		return renderJSON(card)
	case StyleQuick:
		return renderQuick(card), nil
	case StyleRich:
		return renderRich(card), nil
	default:
		return renderDefault(card), nil
	}
}

func renderJSON(card *ReportCard) (string, error) {
	if card.RawJSON != nil {
		return renderRawJSON(card)
	}
	sorted := SortRowsBySeverity(card.Rows)
	payload := cardToPayload(card, sorted)
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal report card json: %w", err)
	}
	if len(data) < MaxJSONBytes {
		return string(data), nil
	}
	return trimJSONPayload(payload, sorted)
}

func renderRawJSON(card *ReportCard) (string, error) {
	rawBytes, err := json.Marshal(card.RawJSON)
	if err != nil {
		return "", fmt.Errorf("marshal raw json: %w", err)
	}
	var decoded any
	if err := json.Unmarshal(rawBytes, &decoded); err != nil {
		return "", fmt.Errorf("decode raw json: %w", err)
	}
	m, ok := decoded.(map[string]any)
	if !ok {
		if len(rawBytes) < MaxJSONBytes {
			return string(rawBytes), nil
		}
		sorted := SortRowsBySeverity(card.Rows)
		return trimJSONPayload(cardToPayload(card, sorted), sorted)
	}

	enriched := make(map[string]any, len(m)+4)
	maps.Copy(enriched, m)
	if card.JobID != "" {
		enriched["job_id"] = card.JobID
	}
	if card.ExpiresIn != "" {
		enriched["expires_in"] = card.ExpiresIn
	}
	data, err := json.Marshal(enriched)
	if err != nil {
		return "", fmt.Errorf("marshal enriched raw json: %w", err)
	}
	if len(data) < MaxJSONBytes {
		return string(data), nil
	}
	if trimmed, okTrim := tryTrimRawRows(enriched); okTrim {
		return trimmed, nil
	}
	sorted := SortRowsBySeverity(card.Rows)
	return trimJSONPayload(cardToPayload(card, sorted), sorted)
}

func tryTrimRawRows(enriched map[string]any) (string, bool) {
	rawRows, ok := enriched["rows"].([]any)
	if !ok || len(rawRows) == 0 {
		return "", false
	}
	sorted := make([]any, len(rawRows))
	copy(sorted, rawRows)
	sort.SliceStable(sorted, func(i, j int) bool {
		return rawRowRank(sorted[i]) < rawRowRank(sorted[j])
	})
	nonCritStart := len(sorted)
	for i, item := range sorted {
		if rawRowRank(item) >= 2 {
			nonCritStart = i
			break
		}
	}

	data, keep := binarySearchMaxJSON(len(sorted)-nonCritStart, func(k int) any {
		kept := nonCritStart + k
		enriched["rows"] = sorted[:kept]
		enriched["truncated"] = true
		enriched["omitted_rows"] = len(sorted) - kept
		return enriched
	})
	if keep < 0 {
		return "", false
	}
	return string(data), true
}

func binarySearchMaxJSON(maxCount int, build func(keep int) any) ([]byte, int) {
	lo, hi := 0, maxCount
	var bestBytes []byte
	bestKeep := -1
	for lo <= hi {
		mid := lo + (hi-lo)/2
		data, err := json.Marshal(build(mid))
		if err == nil && len(data) < MaxJSONBytes {
			bestBytes = data
			bestKeep = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return bestBytes, bestKeep
}

func rawRowRank(item any) int {
	if m, ok := item.(map[string]any); ok {
		if s, ok := m["status"].(string); ok {
			return severityRank(s)
		}
	}
	return 2
}

func cardToPayload(card *ReportCard, sorted []TableRow) *jsonReportPayload {
	c := *card
	c.Rows = sorted
	return &jsonReportPayload{ReportCard: c}
}

func trimJSONPayload(payload *jsonReportPayload, sorted []TableRow) (string, error) {
	total := len(sorted)
	nonCritStart := total
	for i, r := range sorted {
		if severityRank(r.Status) >= 2 {
			nonCritStart = i
			break
		}
	}

	data, bestKeep := binarySearchMaxJSON(total-nonCritStart, func(k int) any {
		kept := nonCritStart + k
		candidate := *payload
		candidate.Rows = sorted[:kept]
		candidate.Truncated = true
		candidate.OmittedRows = total - kept
		return candidate
	})
	if bestKeep >= 0 {
		return string(data), nil
	}

	payload.SparkValues = nil
	payload.HealthStates = nil
	payload.Notes = nil
	payload.Truncated = true
	emBytes, emKeep := binarySearchMaxJSON(total, func(k int) any {
		candidate := *payload
		candidate.Rows = sorted[:k]
		candidate.OmittedRows = total - k
		return candidate
	})
	if emKeep >= 0 {
		return string(emBytes), nil
	}

	minimal := jsonReportPayload{
		ReportCard: ReportCard{
			Title:     ClipWidth(payload.Title, 64),
			ToolName:  payload.ToolName,
			Status:    payload.Status,
			JobID:     payload.JobID,
			ExpiresIn: payload.ExpiresIn,
		},
		Truncated:   true,
		OmittedRows: total,
	}
	minBytes, err := json.Marshal(minimal)
	if err != nil {
		return "", fmt.Errorf("marshal minimal json: %w", err)
	}
	return string(minBytes), nil
}

func renderDefault(card *ReportCard) string {
	var lines []string

	leftTitle := resolveTitle(card)
	if card.Subtitle != "" {
		leftTitle = leftTitle + " — " + card.Subtitle
	}
	rightMeta := strings.TrimSpace(FormatStatusTag(card.Status) + " " + formatDuration(card.DurationMS))
	lines = append(lines,
		FitExact(leftTitle, 40)+"│"+FitRight(rightMeta, 31),
		strings.Repeat("═", 40)+"╤"+strings.Repeat("═", 31),
	)

	for _, mLine := range wrapText(buildMetaLine(card), defaultWidth) {
		lines = append(lines, FitExact(mLine, defaultWidth))
	}
	for _, sLine := range wrapText(card.Summary, defaultWidth) {
		lines = append(lines, FitExact(sLine, defaultWidth))
	}
	for _, mLine := range formatMetricsTwoCol(card.Metrics, defaultWidth) {
		lines = append(lines, FitExact(mLine, defaultWidth))
	}
	if len(card.SparkValues) > 0 || len(card.HealthStates) > 0 {
		lines = append(lines, FitExact(formatVisualRow(card, 24), defaultWidth))
	}

	sortedRows := SortRowsBySeverity(card.Rows)
	if len(card.Headers) > 0 || len(sortedRows) > 0 {
		lines = append(lines, strings.Repeat("─", defaultWidth))
		lines = append(lines, renderTableLines(card.Headers, sortedRows, defaultWidth)...)
	}
	for _, nLine := range wrapNotes(card.Notes, defaultWidth) {
		lines = append(lines, FitExact(nLine, defaultWidth))
	}
	if footer := buildFooterLine(card); footer != "" {
		lines = append(lines, strings.Repeat("─", defaultWidth))
		for _, fLine := range wrapText(footer, defaultWidth) {
			lines = append(lines, FitExact(fLine, defaultWidth))
		}
	}
	return strings.Join(lines, "\n")
}

func renderQuick(card *ReportCard) string {
	var lines []string

	header := strings.TrimSpace(FormatStatusTag(card.Status) + " " + resolveTitle(card))
	if dur := formatDuration(card.DurationMS); dur != "" {
		header += " " + dur
	}
	lines = append(lines, ClipWidth(header, quickWidth))
	if meta := buildMetaLine(card); meta != "" {
		lines = append(lines, ClipWidth(meta, quickWidth))
	}
	lines = append(lines, strings.Repeat("─", quickWidth))

	for _, sLine := range wrapText(card.Summary, quickWidth) {
		lines = append(lines, ClipWidth(sLine, quickWidth))
	}
	for _, m := range card.Metrics {
		lines = append(lines, ClipWidth(m.Label+": "+m.Value, quickWidth))
	}
	if len(card.SparkValues) > 0 {
		lines = append(lines, ClipWidth("Trend: "+Sparkline(card.SparkValues, 20), quickWidth))
	}
	if len(card.HealthStates) > 0 {
		lines = append(lines, ClipWidth("State: "+HealthStrip(card.HealthStates, 20), quickWidth))
	}

	sortedRows := SortRowsBySeverity(card.Rows)
	if len(sortedRows) > 0 {
		lines = append(lines, strings.Repeat("─", quickWidth))
		for _, r := range sortedRows {
			rowText := FormatStatusTag(r.Status)
			if len(r.Cells) > 0 {
				rowText += " " + strings.Join(r.Cells, " ")
			}
			lines = append(lines, ClipWidth(rowText, quickWidth))
		}
	}
	for _, note := range card.Notes {
		lines = append(lines, ClipWidth("• "+note, quickWidth))
	}
	if footer := buildFooterLine(card); footer != "" {
		lines = append(lines,
			strings.Repeat("─", quickWidth),
			ClipWidth(footer, quickWidth),
		)
	}
	return strings.Join(lines, "\n")
}

func renderRich(card *ReportCard) string {
	lines := make([]string, 0, 16+len(card.Rows))
	lines = append(lines, "╔"+strings.Repeat("═", richWidth-2)+"╗")

	title := resolveTitle(card)
	if card.Subtitle != "" {
		title += " — " + card.Subtitle
	}
	rightStatus := strings.TrimSpace(FormatStatusTag(card.Status) + " " + formatDuration(card.DurationMS))
	lines = append(lines, richBoxLine(FitExact(title, 48)+" "+FitRight(rightStatus, 23)))
	for _, mLine := range wrapText(buildMetaLine(card), richInnerWidth) {
		lines = append(lines, richBoxLine(mLine))
	}
	lines = append(lines, "╠"+strings.Repeat("═", richWidth-2)+"╣")

	if card.Summary != "" {
		for _, sLine := range wrapText(card.Summary, richInnerWidth) {
			lines = append(lines, richBoxLine(sLine))
		}
		lines = append(lines, "╟"+strings.Repeat("─", richWidth-2)+"╢")
	}

	lines = append(lines, renderRichSideBySide(card)...)

	sortedRows := SortRowsBySeverity(card.Rows)
	if len(card.Headers) > 0 || len(sortedRows) > 0 {
		lines = append(lines, "╟"+strings.Repeat("─", richWidth-2)+"╢")
		for _, tLine := range renderTableLines(card.Headers, sortedRows, richInnerWidth) {
			lines = append(lines, richBoxLine(tLine))
		}
	}
	if len(card.Notes) > 0 {
		lines = append(lines, "╟"+strings.Repeat("─", richWidth-2)+"╢")
		for _, nLine := range wrapNotes(card.Notes, richInnerWidth) {
			lines = append(lines, richBoxLine(nLine))
		}
	}

	lines = append(lines,
		"╟"+strings.Repeat("─", richWidth-2)+"╢",
		richBoxLine("Legend: █ OK  ▒ WARN  ! FAIL  · empty  ▁..█ trend"),
	)
	for _, fLine := range wrapText(buildFooterLine(card), richInnerWidth) {
		lines = append(lines, richBoxLine(fLine))
	}
	lines = append(lines, "╚"+strings.Repeat("═", richWidth-2)+"╝")
	return strings.Join(lines, "\n")
}

func renderRichSideBySide(card *ReportCard) []string {
	const leftW, rightW = 38, 31
	rightPanel := []string{
		"Trend:  " + Sparkline(card.SparkValues, 23),
		"Health: " + HealthStrip(card.HealthStates, 23),
	}
	if len(card.SparkValues) > 0 {
		last := card.SparkValues[len(card.SparkValues)-1]
		maxVal := last
		for _, v := range card.SparkValues {
			maxVal = max(maxVal, v)
		}
		rightPanel = append(rightPanel, "Load:   "+LatencyBar(last, maxVal, 23))
	}

	rowCount := max(len(card.Metrics), len(rightPanel))
	out := make([]string, 0, rowCount)
	for i := range rowCount {
		leftText, rightText := "", ""
		if i < len(card.Metrics) {
			leftText = card.Metrics[i].Label + ": " + card.Metrics[i].Value
		}
		if i < len(rightPanel) {
			rightText = rightPanel[i]
		}
		out = append(out, richBoxLine(FitExact(leftText, leftW)+" │ "+FitExact(rightText, rightW)))
	}
	return out
}

func richBoxLine(content string) string { return "║ " + FitExact(content, richInnerWidth) + " ║" }

func resolveTitle(card *ReportCard) string {
	if t := strings.TrimSpace(card.Title); t != "" {
		return t
	}
	if t := strings.TrimSpace(card.ToolName); t != "" {
		return t
	}
	return "NETUTILS REPORT"
}

func formatDuration(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return strconv.FormatInt(ms, 10) + "ms"
}

func buildMetaLine(card *ReportCard) string {
	var parts []string
	if card.ToolName != "" && card.Title != "" && card.ToolName != card.Title {
		parts = append(parts, "Tool: "+card.ToolName)
	}
	if card.Target != "" {
		parts = append(parts, "Target: "+card.Target)
	}
	return strings.Join(parts, "  |  ")
}

func buildFooterLine(card *ReportCard) string {
	switch {
	case card.JobID != "" && card.ExpiresIn != "":
		return "job_id: " + card.JobID + "  |  expires_in: " + card.ExpiresIn
	case card.JobID != "":
		return "job_id: " + card.JobID
	case card.ExpiresIn != "":
		return "expires_in: " + card.ExpiresIn
	default:
		return ""
	}
}
