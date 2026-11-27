package ascii

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuneHelpers(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 5, RuneLen("hello"))
	assert.Equal(t, 4, RuneLen("▁▂▃▄"))
	assert.Equal(t, "hi   ", PadRight("hi", 5))
	assert.Equal(t, "hello", PadRight("hello", 3))
	assert.Equal(t, "   hi", PadLeft("hi", 5))
	assert.Equal(t, "hello", PadLeft("hello", 3))

	clipped := ClipWidth("abcdef", 4)
	assert.Equal(t, "abc…", clipped)
	assert.Equal(t, 4, RuneLen(clipped))
	assert.Equal(t, "…", ClipWidth("abcdef", 1))
	assert.Empty(t, ClipWidth("abcdef", 0))

	fittedShort := FitExact("ok", 6)
	assert.Equal(t, "ok    ", fittedShort)
	assert.Equal(t, 6, RuneLen(fittedShort))

	fittedRightShort := FitRight("ok", 6)
	assert.Equal(t, "    ok", fittedRightShort)
	assert.Equal(t, 6, RuneLen(fittedRightShort))

	fittedRightLong := FitRight("▁▂▃▄▅▆▇█", 5)
	assert.Equal(t, "▁▂▃▄…", fittedRightLong)
	assert.Equal(t, 5, RuneLen(fittedRightLong))
	assert.Empty(t, FitRight("ok", 0))

	fittedLong := FitExact("▁▂▃▄▅▆▇█", 5)
	assert.Equal(t, "▁▂▃▄…", fittedLong)
	assert.Equal(t, 5, RuneLen(fittedLong))

	sanitized := FitExact("line1\nline2\tval", 15)
	assert.Equal(t, 15, RuneLen(sanitized))
	assert.NotContains(t, sanitized, "\n")
	assert.NotContains(t, sanitized, "\t")
}

func TestVisualPrimitives(t *testing.T) {
	t.Parallel()

	spark := Sparkline([]float64{0, 10, 20, 40, 80}, 8)
	assert.Equal(t, 8, RuneLen(spark))
	assert.True(t, strings.HasPrefix(spark, "─"))
	assert.True(t, strings.HasSuffix(spark, "───"))

	downSpark := Sparkline([]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, 6)
	assert.Equal(t, 6, RuneLen(downSpark))

	emptySpark := Sparkline(nil, 5)
	assert.Equal(t, "─────", emptySpark)

	strip := HealthStrip([]string{"ok", "WARN", "fail", ""}, 6)
	assert.Equal(t, "█▒!···", strip)
	assert.Equal(t, 6, RuneLen(strip))

	// Downsampling must preserve worst-case FAIL/WARN within a bucket.
	downStrip := HealthStrip([]string{"OK", "FAIL", "OK", "OK"}, 2)
	assert.Equal(t, "!█", downStrip)

	bar := LatencyBar(50, 100, 10)
	assert.Equal(t, 10, RuneLen(bar))
	assert.Equal(t, "█████░░░░░", bar)

	zeroBar := LatencyBar(0, 100, 6)
	assert.Equal(t, "░░░░░░", zeroBar)

	assert.Equal(t, "[OK]", FormatStatusTag("ok"))
	assert.Equal(t, "[WARN]", FormatStatusTag("warning"))
	assert.Equal(t, "[FAIL]", FormatStatusTag("error"))
	assert.Equal(t, "[INFO]", FormatStatusTag("info"))
}

func TestNormalizeStyle(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want string
	}{
		{"", StyleDefault},
		{"  ", StyleDefault},
		{"DEFAULT", StyleDefault},
		{"Quick", StyleQuick},
		{" rich ", StyleRich},
		{"JSON", StyleJSON},
	}
	for _, tc := range cases {
		got, err := NormalizeStyle(tc.in)
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}

	_, err := NormalizeStyle("xml")
	require.Error(t, err)
}

func TestSortRowsBySeverity(t *testing.T) {
	t.Parallel()

	input := []TableRow{
		{Status: "OK", Cells: []string{"ok-1"}},
		{Status: "INFO", Cells: []string{"info-1"}},
		{Status: "WARN", Cells: []string{"warn-1"}},
		{Status: "FAIL", Cells: []string{"fail-1"}},
		{Status: "OK", Cells: []string{"ok-2"}},
		{Status: "WARN", Cells: []string{"warn-2"}},
		{Status: "FAIL", Cells: []string{"fail-2"}},
	}

	sorted := SortRowsBySeverity(input)
	require.Len(t, sorted, len(input))

	gotOrder := make([]string, len(sorted))
	for i, r := range sorted {
		gotOrder[i] = r.Cells[0]
	}
	assert.Equal(t, []string{"fail-1", "fail-2", "warn-1", "warn-2", "ok-1", "info-1", "ok-2"}, gotOrder)
	// Input slice must remain untouched.
	assert.Equal(t, "ok-1", input[0].Cells[0])
}

func sampleCard() *ReportCard {
	return &ReportCard{
		Title:      "TCP Port Scan",
		Subtitle:   "prod-edge-01",
		ToolName:   "tcp_port_scan",
		Target:     "10.0.4.12",
		Status:     "WARN",
		JobID:      "job-9921",
		ExpiresIn:  "14m30s",
		DurationMS: 142,
		Summary:    "Scanned 4 critical ports on prod-edge-01 with one closed port and one high-latency handshake.",
		Metrics: []MetricKV{
			{Label: "Open", Value: "2"},
			{Label: "Warn", Value: "1"},
			{Label: "Closed", Value: "1"},
			{Label: "Avg RTT", Value: "18.4ms"},
		},
		Headers:      []string{"PORT", "STATE", "RTT", "SERVICE"},
		SparkValues:  []float64{12.1, 14.0, 42.5, 19.3, 0, 15.2},
		HealthStates: []string{"OK", "WARN", "FAIL", "OK"},
		Rows: []TableRow{
			{Status: "OK", Cells: []string{"443/tcp", "open", "12.1ms", "https"}},
			{Status: "WARN", Cells: []string{"8443/tcp", "slow", "42.5ms", "alt-https"}},
			{Status: "FAIL", Cells: []string{"22/tcp", "refused", "0ms", "ssh"}},
			{Status: "INFO", Cells: []string{"80/tcp", "redirect", "14.0ms", "http"}},
		},
		Notes: []string{"Port 22 refused connection from scanner subnet."},
	}
}

func TestRenderDefaultExact72Cols(t *testing.T) {
	t.Parallel()

	out, err := Render(sampleCard(), StyleDefault)
	require.NoError(t, err)

	lines := strings.Split(out, "\n")
	require.GreaterOrEqual(t, len(lines), 8)
	for i, line := range lines {
		assert.Equal(t, 72, RuneLen(line), "line %d (%q) must be 72 runes", i+1, line)
	}

	assert.True(t, strings.HasSuffix(lines[0], "│"+strings.Repeat(" ", 19)+"[WARN] 142ms"), "header right side must be flush right: %q", lines[0])
	assert.Equal(t, strings.Repeat("═", 40)+"╤"+strings.Repeat("═", 31), lines[1])
	assert.Contains(t, out, "job_id: job-9921")
	assert.Contains(t, out, "expires_in: 14m30s")

	failIdx := strings.Index(out, "22/tcp")
	warnIdx := strings.Index(out, "8443/tcp")
	okIdx := strings.Index(out, "443/tcp")
	assert.Greater(t, failIdx, -1)
	assert.Less(t, failIdx, warnIdx)
	assert.Less(t, warnIdx, okIdx)
}

func TestRenderQuickMax40ColsBorderless(t *testing.T) {
	t.Parallel()

	out, err := Render(sampleCard(), StyleQuick)
	require.NoError(t, err)

	for _, forbidden := range []string{"╔", "╗", "║", "╚", "╝", "╠", "╣"} {
		assert.NotContains(t, out, forbidden)
	}
	assert.Contains(t, out, "───")

	lines := strings.Split(out, "\n")
	require.NotEmpty(t, lines)
	for i, line := range lines {
		assert.LessOrEqual(t, RuneLen(line), 40, "line %d (%q) exceeds 40 runes", i+1, line)
	}

	failIdx := strings.Index(out, "22/tcp")
	warnIdx := strings.Index(out, "8443/tcp")
	okIdx := strings.Index(out, "443/tcp")
	assert.Greater(t, failIdx, -1)
	assert.Less(t, failIdx, warnIdx)
	assert.Less(t, warnIdx, okIdx)
}

func TestRenderRichExact76ColsBoxed(t *testing.T) {
	t.Parallel()

	out, err := Render(sampleCard(), StyleRich)
	require.NoError(t, err)

	lines := strings.Split(out, "\n")
	require.GreaterOrEqual(t, len(lines), 10)
	assert.True(t, strings.HasPrefix(lines[0], "╔") && strings.HasSuffix(lines[0], "╗"))
	assert.True(t, strings.HasSuffix(lines[1], "           [WARN] 142ms ║"), "rich header status must be flush right: %q", lines[1])
	assert.True(t, strings.HasPrefix(lines[len(lines)-1], "╚") && strings.HasSuffix(lines[len(lines)-1], "╝"))

	for i, line := range lines {
		assert.Equal(t, 76, RuneLen(line), "line %d (%q) must be 76 runes", i+1, line)
	}
	assert.Contains(t, out, "╠")
	assert.Contains(t, out, "╟")
	assert.Contains(t, out, "Legend:")

	failIdx := strings.Index(out, "22/tcp")
	warnIdx := strings.Index(out, "8443/tcp")
	okIdx := strings.Index(out, "443/tcp")
	assert.Greater(t, failIdx, -1)
	assert.Less(t, failIdx, warnIdx)
	assert.Less(t, warnIdx, okIdx)
}

func TestRenderJSONWireCap500Rows(t *testing.T) {
	t.Parallel()

	rows := make([]TableRow, 0, 500)
	for i := range 500 {
		status := "OK"
		switch i {
		case 120, 350:
			status = "FAIL"
		case 200, 410:
			status = "WARN"
		}
		rows = append(rows, TableRow{
			Status: status,
			Cells: []string{
				fmt.Sprintf("host-%03d.internal.example.net", i),
				fmt.Sprintf("10.20.%d.%d", i/256, i%256),
				"23.4ms",
				"healthy-response-payload-padding-for-wire-cap-check",
			},
		})
	}

	card := &ReportCard{
		Title:     "Bulk DNS & Reachability Sweep",
		ToolName:  "dns_reverse_batch",
		Target:    "10.20.0.0/23",
		Status:    "FAIL",
		JobID:     "job-500",
		ExpiresIn: "15m0s",
		Headers:   []string{"HOST", "IP", "RTT", "NOTE"},
		Rows:      rows,
	}

	out, err := Render(card, StyleJSON)
	require.NoError(t, err)
	assert.Less(t, len(out), MaxJSONBytes, "JSON output must stay strictly under 18944 bytes")

	var decoded struct {
		JobID       string     `json:"job_id"`
		ExpiresIn   string     `json:"expires_in"`
		Truncated   bool       `json:"truncated"`
		OmittedRows int        `json:"omitted_rows"`
		Rows        []TableRow `json:"rows"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &decoded))
	assert.Equal(t, "job-500", decoded.JobID)
	assert.Equal(t, "15m0s", decoded.ExpiresIn)
	assert.True(t, decoded.Truncated)
	assert.Positive(t, decoded.OmittedRows)
	assert.Equal(t, 500, len(decoded.Rows)+decoded.OmittedRows)

	// Verify all FAIL and WARN rows are preserved at the front.
	require.GreaterOrEqual(t, len(decoded.Rows), 4)
	assert.Equal(t, "FAIL", decoded.Rows[0].Status)
	assert.Equal(t, "FAIL", decoded.Rows[1].Status)
	assert.Equal(t, "WARN", decoded.Rows[2].Status)
	assert.Equal(t, "WARN", decoded.Rows[3].Status)
}

func TestRenderJSONRawEnrichmentAndCap(t *testing.T) {
	t.Parallel()

	rawRows := make([]map[string]any, 0, 500)
	for i := range 500 {
		st := "OK"
		if i == 250 {
			st = "FAIL"
		}
		rawRows = append(rawRows, map[string]any{
			"status": st,
			"host":   fmt.Sprintf("node-%03d.lan", i),
			"detail": "raw-json-wire-cap-verification-padding-string",
		})
	}

	card := &ReportCard{
		JobID:     "raw-job-1",
		ExpiresIn: "10m",
		RawJSON: map[string]any{
			"tool": "ping",
			"rows": rawRows,
		},
	}

	out, err := Render(card, StyleJSON)
	require.NoError(t, err)
	assert.Less(t, len(out), MaxJSONBytes)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &decoded))
	assert.Equal(t, "raw-job-1", decoded["job_id"])
	assert.Equal(t, "10m", decoded["expires_in"])
	assert.Equal(t, true, decoded["truncated"])

	keptRows, ok := decoded["rows"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, keptRows)
	firstRow, ok := keptRows[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "FAIL", firstRow["status"])
}

func TestRenderNilAndInvalidStyle(t *testing.T) {
	t.Parallel()

	_, err := Render(nil, StyleDefault)
	require.Error(t, err)

	_, err = Render(&ReportCard{Title: "x"}, "invalid")
	require.Error(t, err)

	// Empty style defaults to 72-col default rendering.
	out, err := Render(&ReportCard{Title: "Empty Card"}, "")
	require.NoError(t, err)
	for _, line := range strings.Split(out, "\n") {
		assert.Equal(t, 72, RuneLen(line))
	}
}

func TestRenderLongMetaAndJobIDWrapped(t *testing.T) {
	t.Parallel()

	longJobID := "job-20261127-022857-abcdef1234567890-fedcba0987654321"
	longTarget := "edge-gateway-01.us-west-2.internal.example.net:8443/healthz"
	card := &ReportCard{
		Title:      "Bulk Reachability Check",
		ToolName:   "dns_reverse_batch",
		Target:     longTarget,
		Status:     "OK",
		DurationMS: 206,
		JobID:      longJobID,
		ExpiresIn:  "14m30s",
	}

	defOut, err := Render(card, StyleDefault)
	require.NoError(t, err)
	defLines := strings.Split(defOut, "\n")
	for i, line := range defLines {
		assert.Equal(t, 72, RuneLen(line), "default line %d (%q) must be 72 runes", i+1, line)
	}
	assert.True(t, strings.HasSuffix(defLines[0], "│"+strings.Repeat(" ", 21)+"[OK] 206ms"), "header right side must be flush right: %q", defLines[0])
	assert.Contains(t, defOut, longTarget)
	assert.Contains(t, defOut, "job_id: "+longJobID)
	assert.Contains(t, defOut, "expires_in: 14m30s")
	assert.NotContains(t, defOut, "Job:")

	richOut, err := Render(card, StyleRich)
	require.NoError(t, err)
	richLines := strings.Split(richOut, "\n")
	for i, line := range richLines {
		assert.Equal(t, 76, RuneLen(line), "rich line %d (%q) must be 76 runes", i+1, line)
	}
	assert.True(t, strings.HasSuffix(richLines[1], "             [OK] 206ms ║"), "rich header right side must be flush right: %q", richLines[1])
	assert.Contains(t, richOut, longTarget)
	assert.Contains(t, richOut, "job_id: "+longJobID)
	assert.Contains(t, richOut, "expires_in: 14m30s")
	assert.NotContains(t, richOut, "Job:")
}
