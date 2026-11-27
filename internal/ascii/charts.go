// Package ascii provides three-tier terminal and wire-capped JSON report rendering.
package ascii

import (
	"math"
	"strings"
	"unicode/utf8"
)

const (
	statusFAIL = "FAIL"
	statusWARN = "WARN"
	statusOK   = "OK"
	statusINFO = "INFO"
)

var sparkBlocks = []rune("▁▂▃▄▅▆▇█")

// RuneLen returns the number of Unicode runes in s.
func RuneLen(s string) int {
	return utf8.RuneCountInString(s)
}

// PadRight pads s on the right with spaces until its rune count reaches width.
// If s already meets or exceeds width, or width is non-positive, s is returned sanitized.
func PadRight(s string, width int) string {
	return padSpaces(s, width, false)
}

// PadLeft pads s on the left with spaces until its rune count reaches width.
// If s already meets or exceeds width, or width is non-positive, s is returned sanitized.
func PadLeft(s string, width int) string {
	return padSpaces(s, width, true)
}

func padSpaces(s string, width int, left bool) string {
	clean := sanitizeLine(s)
	if width <= 0 {
		return clean
	}
	n := utf8.RuneCountInString(clean)
	if n >= width {
		return clean
	}
	pad := strings.Repeat(" ", width-n)
	if left {
		return pad + clean
	}
	return clean + pad
}

// ClipWidth truncates s to at most width runes, appending "…" when truncated.
func ClipWidth(s string, width int) string {
	if width <= 0 {
		return ""
	}
	clean := sanitizeLine(s)
	runes := []rune(clean)
	if len(runes) <= width {
		return clean
	}
	if width == 1 {
		return "…"
	}
	return string(runes[:width-1]) + "…"
}

// FitExact fits s to exactly width runes by truncating with "…" or padding spaces on the right.
func FitExact(s string, width int) string {
	if width <= 0 {
		return ""
	}
	return PadRight(ClipWidth(s, width), width)
}

// FitRight fits s to exactly width runes by truncating with "…" or padding spaces on the left.
func FitRight(s string, width int) string {
	if width <= 0 {
		return ""
	}
	return PadLeft(ClipWidth(s, width), width)
}

// Sparkline renders a Unicode sparkline of exact rune length width using "▁▂▃▄▅▆▇█"
// and "─" for zero, missing, or invalid values.
func Sparkline(values []float64, width int) string {
	if width <= 0 {
		return ""
	}
	if len(values) == 0 {
		return strings.Repeat("─", width)
	}

	sampled := resampleSparkValues(values, width)
	minPos := math.MaxFloat64
	maxVal := 0.0
	hasPos := false
	for _, v := range sampled {
		if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
			continue
		}
		if !hasPos || v < minPos {
			minPos = v
		}
		if v > maxVal {
			maxVal = v
		}
		hasPos = true
	}

	out := make([]rune, width)
	for i := range width {
		if i >= len(sampled) {
			out[i] = '─'
			continue
		}
		v := sampled[i]
		if !hasPos || math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
			out[i] = '─'
			continue
		}
		if maxVal == minPos {
			out[i] = sparkBlocks[3]
			continue
		}
		norm := (v - minPos) / (maxVal - minPos)
		idx := min(max(int(math.Round(norm*float64(len(sparkBlocks)-1))), 0), len(sparkBlocks)-1)
		out[i] = sparkBlocks[idx]
	}
	return string(out)
}

// HealthStrip renders a compact status strip of exact rune length width,
// mapping OK->█, WARN->▒, FAIL->!, and empty/unknown->·.
func HealthStrip(statuses []string, width int) string {
	if width <= 0 {
		return ""
	}
	if len(statuses) == 0 {
		return strings.Repeat("·", width)
	}

	sampled := resampleHealthStatuses(statuses, width)
	out := make([]rune, width)
	for i := range width {
		if i >= len(sampled) {
			out[i] = '·'
			continue
		}
		switch normalizeStatus(sampled[i]) {
		case statusOK:
			out[i] = '█'
		case statusWARN:
			out[i] = '▒'
		case statusFAIL:
			out[i] = '!'
		case statusINFO:
			out[i] = '▓'
		default:
			out[i] = '·'
		}
	}
	return string(out)
}

// LatencyBar renders a proportional horizontal bar of exact rune length width using "█▓░".
func LatencyBar(val, maxVal float64, width int) string {
	if width <= 0 {
		return ""
	}
	if math.IsNaN(val) || math.IsInf(val, 0) || math.IsNaN(maxVal) || math.IsInf(maxVal, 0) || maxVal <= 0 || val <= 0 {
		return strings.Repeat("░", width)
	}

	ratio := val / maxVal
	if ratio > 1 {
		ratio = 1
	}
	scaled := ratio * float64(width)
	full := int(math.Floor(scaled))
	frac := scaled - float64(full)

	out := make([]rune, width)
	for i := range width {
		switch {
		case i < full:
			out[i] = '█'
		case i == full && (frac >= 0.25 || (val > 0 && full == 0)):
			out[i] = '▓'
		default:
			out[i] = '░'
		}
	}
	return string(out)
}

// FormatStatusTag formats a status string into a canonical bracketed tag ([OK], [WARN], [FAIL], or [INFO]).
func FormatStatusTag(status string) string {
	switch normalizeStatus(status) {
	case statusFAIL:
		return "[FAIL]"
	case statusWARN:
		return "[WARN]"
	case statusOK:
		return "[OK]"
	default:
		return "[INFO]"
	}
}

func sanitizeLine(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func normalizeStatus(status string) string {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case statusFAIL, "ERROR", "ERR", "CRITICAL", "DOWN":
		return statusFAIL
	case statusWARN, "WARNING", "DEGRADED":
		return statusWARN
	case statusOK, "PASS", "UP", "HEALTHY":
		return statusOK
	case "":
		return ""
	default:
		return statusINFO
	}
}

func severityRank(status string) int {
	switch normalizeStatus(status) {
	case statusFAIL:
		return 0
	case statusWARN:
		return 1
	default:
		return 2
	}
}

func resampleSparkValues(values []float64, width int) []float64 {
	if len(values) <= width {
		return values
	}
	out := make([]float64, width)
	n := len(values)
	for i := range width {
		start := i * n / width
		end := min(max((i+1)*n/width, start+1), n)
		sum, count := 0.0, 0
		for j := start; j < end; j++ {
			v := values[j]
			if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
				continue
			}
			sum += v
			count++
		}
		if count > 0 {
			out[i] = sum / float64(count)
		}
	}
	return out
}

func resampleHealthStatuses(statuses []string, width int) []string {
	if len(statuses) <= width {
		return statuses
	}
	out := make([]string, width)
	n := len(statuses)
	for i := range width {
		start := i * n / width
		end := min(max((i+1)*n/width, start+1), n)
		best := ""
		bestRank := 3
		for j := start; j < end; j++ {
			st := normalizeStatus(statuses[j])
			if st == "" {
				continue
			}
			r := severityRank(st)
			if r < bestRank {
				bestRank = r
				best = st
			}
		}
		out[i] = best
	}
	return out
}

func wrapText(s string, width int) []string {
	if width <= 0 {
		return nil
	}
	clean := strings.TrimSpace(sanitizeLine(s))
	if clean == "" {
		return nil
	}
	words := strings.Fields(clean)
	if len(words) == 0 {
		return nil
	}

	var lines []string
	var cur strings.Builder
	curLen := 0

	for _, w := range words {
		wLen := RuneLen(w)
		if wLen > width {
			if curLen > 0 {
				lines = append(lines, cur.String())
				cur.Reset()
				curLen = 0
			}
			runes := []rune(w)
			for len(runes) > width {
				lines = append(lines, string(runes[:width]))
				runes = runes[width:]
			}
			if len(runes) > 0 {
				cur.WriteString(string(runes))
				curLen = len(runes)
			}
			continue
		}

		if curLen == 0 {
			cur.WriteString(w)
			curLen = wLen
			continue
		}
		if curLen+1+wLen <= width {
			cur.WriteByte(' ')
			cur.WriteString(w)
			curLen += 1 + wLen
			continue
		}
		lines = append(lines, cur.String())
		cur.Reset()
		cur.WriteString(w)
		curLen = wLen
	}
	if curLen > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}

func wrapNotes(notes []string, width int) []string {
	var out []string
	for _, note := range notes {
		for idx, wLine := range wrapText(note, width-2) {
			prefix := "  "
			if idx == 0 {
				prefix = "• "
			}
			out = append(out, prefix+wLine)
		}
	}
	return out
}

func renderTableLines(headers []string, rows []TableRow, width int) []string {
	const statusColWidth = 6 // "[FAIL]"
	numCols := len(headers)
	for _, r := range rows {
		numCols = max(numCols, len(r.Cells))
	}
	if numCols == 0 {
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, FitExact(FormatStatusTag(r.Status), width))
		}
		return out
	}

	availCells := max(width-statusColWidth-1, numCols)
	colWidths := computeColWidths(headers, rows, numCols, availCells)

	var out []string
	if len(headers) > 0 {
		out = append(out,
			FitExact(formatTableRecord("STAT", headers, colWidths, statusColWidth), width),
			strings.Repeat("─", width),
		)
	}
	for _, r := range rows {
		out = append(out, FitExact(formatTableRecord(FormatStatusTag(r.Status), r.Cells, colWidths, statusColWidth), width))
	}
	return out
}

func computeColWidths(headers []string, rows []TableRow, numCols, avail int) []int {
	usable := max(avail-(numCols-1), numCols)
	desired := make([]int, numCols)
	for i := 0; i < numCols && i < len(headers); i++ {
		desired[i] = max(desired[i], RuneLen(headers[i]))
	}
	for _, r := range rows {
		for i := 0; i < numCols && i < len(r.Cells); i++ {
			desired[i] = max(desired[i], RuneLen(r.Cells[i]))
		}
	}

	totalDesired := 0
	for i := range numCols {
		desired[i] = max(desired[i], 4)
		totalDesired += desired[i]
	}

	widths := make([]int, numCols)
	if totalDesired <= usable {
		copy(widths, desired)
		widths[numCols-1] += usable - totalDesired
		return widths
	}

	allocated := 0
	for i := range numCols {
		widths[i] = max(desired[i]*usable/totalDesired, 1)
		allocated += widths[i]
	}
	for allocated < usable {
		for i := range numCols {
			if allocated >= usable {
				break
			}
			widths[i]++
			allocated++
		}
	}
	for i := numCols - 1; i >= 0 && allocated > usable; i-- {
		if widths[i] > 1 {
			shrink := min(widths[i]-1, allocated-usable)
			widths[i] -= shrink
			allocated -= shrink
		}
	}
	return widths
}

func formatTableRecord(tag string, cells []string, colWidths []int, statusW int) string {
	var b strings.Builder
	b.WriteString(FitExact(tag, statusW))
	for i, w := range colWidths {
		b.WriteByte(' ')
		cell := ""
		if i < len(cells) {
			cell = cells[i]
		}
		b.WriteString(FitExact(cell, w))
	}
	return b.String()
}

func formatMetricsTwoCol(metrics []MetricKV, width int) []string {
	if len(metrics) == 0 {
		return nil
	}
	colW := (width - 2) / 2
	out := make([]string, 0, (len(metrics)+1)/2)
	for i := 0; i < len(metrics); i += 2 {
		left := metrics[i].Label + ": " + metrics[i].Value
		if i+1 < len(metrics) {
			right := metrics[i+1].Label + ": " + metrics[i+1].Value
			out = append(out, FitExact(left, colW)+"  "+FitExact(right, width-colW-2))
			continue
		}
		out = append(out, FitExact(left, width))
	}
	return out
}

func formatVisualRow(card *ReportCard, barWidth int) string {
	var parts []string
	if len(card.SparkValues) > 0 {
		parts = append(parts, "Trend: "+Sparkline(card.SparkValues, barWidth))
	}
	if len(card.HealthStates) > 0 {
		parts = append(parts, "Health: "+HealthStrip(card.HealthStates, barWidth))
	}
	return strings.Join(parts, "  ")
}
