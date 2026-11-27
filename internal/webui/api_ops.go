package webui

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/cronmon"
	"github.com/FrankXLT/mcp-adv-netutils/internal/dispatch"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
)

type workspaceSummary struct {
	CronHealthPct     float64 `json:"cron_health_pct"`
	HealthyTargets    int     `json:"healthy_targets"`
	TotalTargets      int     `json:"total_targets"`
	ActiveAlerts      int     `json:"active_alerts"`
	RetainedJobs      int64   `json:"retained_jobs"`
	ArchiveMB         float64 `json:"archive_mb"`
	ArchiveMaxMB      float64 `json:"archive_max_mb"`
	SavedDestinations int     `json:"saved_destinations"`
	SampleCount       int64   `json:"sample_count"`
}

type stripDay struct {
	Label  string  `json:"label"`
	Status string  `json:"status"`
	Detail string  `json:"detail"`
	AvgMs  float64 `json:"avgMs"`
}

type watchlistRow struct {
	Key        string  `json:"key"`
	Target     string  `json:"target"`
	Check      string  `json:"check"`
	Health     string  `json:"health"`
	Hysteresis string  `json:"hysteresis"`
	AvgMS      float64 `json:"avg_ms"`
	MaxMS      float64 `json:"max_ms"`
	LastTick   string  `json:"last_tick"`
}

type jobSummaryRow struct {
	JobID     string `json:"job_id"`
	Tool      string `json:"tool"`
	Target    string `json:"target"`
	Status    string `json:"status"`
	Summary   string `json:"summary"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

type durAgg struct {
	sum   float64
	count int64
	max   float64
}

func (h *studioHandler) handleRun(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !h.requireUnlocked(w, r) {
		return
	}
	if h.dispatcher == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "dispatcher not configured"})
		return
	}
	var req struct {
		Tool     string         `json:"tool"`
		Target   string         `json:"target"`
		Style    string         `json:"style"`
		Ports    any            `json:"ports"`
		Period   string         `json:"period"`
		Baseline string         `json:"baseline"`
		Args     map[string]any `json:"args"`
	}
	if status, msg := decodeLimitedJSON(w, r.Body, maxRunBodySize, &req); status != 0 {
		writeJSON(w, status, map[string]string{"error": msg})
		return
	}
	args := maps.Clone(req.Args)
	if args == nil {
		args = make(map[string]any)
	}
	for _, kv := range [][2]string{{"target", req.Target}, {"period", req.Period}, {"baseline", req.Baseline}} {
		if v := strings.TrimSpace(kv[1]); v != "" {
			if cur, exists := args[kv[0]]; !exists || cur == nil || cur == "" {
				args[kv[0]] = v
			}
		}
	}
	if req.Ports != nil {
		if s, ok := req.Ports.(string); !ok || strings.TrimSpace(s) != "" {
			if _, exists := args["ports"]; !exists {
				args["ports"] = req.Ports
			}
		}
	}
	out, err := h.dispatcher.Dispatch(r.Context(), dispatch.Request{
		Tool: req.Tool, Args: args, Style: req.Style, Source: "web", SkipDeadbolt: true,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *studioHandler) handleCron(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	unlocked := h.isUnlocked(w, r)
	if !unlocked && !h.allowLockedSummary() {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"locked": true, "error": "operator studio locked"})
		return
	}
	period := strings.TrimSpace(r.URL.Query().Get("period"))
	if period == "" {
		period = defaultCronPeriod
	}
	rawRange := strings.TrimSpace(r.URL.Query().Get("range"))
	jobs, cronStatus, stats, wlItems, ok := h.loadWorkspace(r.Context(), w, period, store.JobFilter{Limit: defaultJobsLimit})
	if !ok {
		return
	}
	timeseries, normRange, sampleCount, err := buildCronTimeseries(r.Context(), h.store, cronStatus, rawRange, time.Now().UTC())
	if err != nil {
		writeMappedError(w, err)
		return
	}
	wlRows := buildWatchlistRows(wlItems, cronStatus, jobs)
	resp := cronResponse{
		Locked:     !unlocked,
		Summary:    buildWorkspaceSummary(cronStatus, &stats, wlRows, sampleCount),
		Warmup:     len(cronStatus.DailyStats) < 2,
		Strip:      buildStripDays(cronStatus.DailyStats),
		Watchlist:  []watchlistRow{},
		Jobs:       []jobSummaryRow{},
		Timeseries: timeseries,
		Range:      normRange,
	}
	if unlocked {
		resp.Watchlist = wlRows
		resp.Jobs = toJobSummaryRows(jobs)
		resp.LANInventory = h.findLatestLANInventory(r.Context(), jobs)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *studioHandler) handleJobs(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) || !h.requireUnlocked(w, r) {
		return
	}
	q, limit := r.URL.Query(), defaultJobsLimit
	if rawLim := strings.TrimSpace(q.Get("limit")); rawLim != "" {
		parsed, err := strconv.Atoi(rawLim)
		if err != nil || parsed <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		limit = min(parsed, maxJobsLimit)
	}
	inc := strings.TrimSpace(q.Get("incidents"))
	filter := store.JobFilter{
		ToolName:      strings.TrimSpace(q.Get("tool")),
		Status:        strings.TrimSpace(q.Get("status")),
		IncidentsOnly: inc == "1" || strings.EqualFold(inc, "true"),
		Limit:         limit,
	}
	jobs, cronStatus, stats, wlItems, ok := h.loadWorkspace(r.Context(), w, defaultCronPeriod, filter)
	if !ok {
		return
	}
	wlRows := buildWatchlistRows(wlItems, cronStatus, jobs)
	writeJSON(w, http.StatusOK, struct {
		Jobs    []jobSummaryRow  `json:"jobs"`
		Summary workspaceSummary `json:"summary"`
	}{Jobs: toJobSummaryRows(jobs), Summary: buildWorkspaceSummary(cronStatus, &stats, wlRows, 0)})
}

func (h *studioHandler) handleJobByID(w http.ResponseWriter, r *http.Request, id string) {
	if !requireMethod(w, r, http.MethodGet) || !h.requireUnlocked(w, r) {
		return
	}
	if id == "" || strings.Contains(id, "/") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}
	if h.dispatcher == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "dispatcher not configured"})
		return
	}
	out, err := h.dispatcher.GetJobReport(r.Context(), id, r.URL.Query().Get("style"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
			return
		}
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *studioHandler) handleWatchlist(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodPost) || !h.requireUnlocked(w, r) {
		return
	}
	if h.scheduler == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "scheduler not configured"})
		return
	}
	params := cronmon.ManageParams{Action: "list"}
	if r.Method == http.MethodPost {
		if status, msg := decodeLimitedJSON(w, r.Body, maxRunBodySize, &params); status != 0 {
			writeJSON(w, status, map[string]string{"error": msg})
			return
		}
	}
	res, err := h.scheduler.ManageWatchlist(r.Context(), params)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

//nolint:gocritic // hugeParam: filter value matches store.JobStore.ListJobs signature.
func (h *studioHandler) loadWorkspace(
	ctx context.Context, w http.ResponseWriter, period string, filter store.JobFilter,
) ([]store.JobRecord, *store.CronSummary, store.StoreStats, []cronmon.WatchItem, bool) {
	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "job store not configured"})
		return nil, nil, store.StoreStats{}, nil, false
	}
	cronStatus, err := h.store.GetCronStatus(ctx, period)
	if err != nil {
		writeMappedError(w, err)
		return nil, nil, store.StoreStats{}, nil, false
	}
	jobs, err := h.store.ListJobs(ctx, filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return nil, nil, store.StoreStats{}, nil, false
	}
	stats, err := h.store.Stats(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return nil, nil, store.StoreStats{}, nil, false
	}
	var wlItems []cronmon.WatchItem
	if h.scheduler != nil {
		wlRes, wlErr := h.scheduler.ManageWatchlist(ctx, cronmon.ManageParams{Action: "list"})
		if wlErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": wlErr.Error()})
			return nil, nil, store.StoreStats{}, nil, false
		}
		wlItems = wlRes.Items
	}
	return jobs, cronStatus, stats, wlItems, true
}

func (h *studioHandler) findLatestLANInventory(ctx context.Context, recentJobs []store.JobRecord) *dispatch.LANInventoryView {
	for i := range recentJobs {
		if inv := extractLANInventory(&recentJobs[i]); inv != nil {
			return inv
		}
	}
	var latest *store.JobRecord
	for _, tool := range []string{"recipe_lan_radar", "arp_neighbor_sweep"} {
		found, err := h.store.ListJobs(ctx, store.JobFilter{ToolName: tool, Limit: 1})
		if err == nil && len(found) > 0 && (latest == nil || found[0].CreatedAt > latest.CreatedAt) {
			cp := found[0]
			latest = &cp
		}
	}
	return extractLANInventory(latest)
}

func extractLANInventory(rec *store.JobRecord) *dispatch.LANInventoryView {
	if rec == nil || (rec.ToolName != "recipe_lan_radar" && rec.ToolName != "arp_neighbor_sweep") || strings.TrimSpace(rec.PayloadJSON) == "" {
		return nil
	}
	var env struct {
		LANInventory *dispatch.LANInventoryView `json:"lan_inventory"`
		Physical     []dispatch.LANHostView     `json:"physical"`
		Virtual      []dispatch.LANHostView     `json:"virtual"`
	}
	if err := json.Unmarshal([]byte(rec.PayloadJSON), &env); err != nil {
		return nil
	}
	if env.LANInventory != nil {
		return env.LANInventory
	}
	if len(env.Physical) > 0 || len(env.Virtual) > 0 {
		return &dispatch.LANInventoryView{Physical: env.Physical, Virtual: env.Virtual}
	}
	return nil
}

func buildWorkspaceSummary(cronStatus *store.CronSummary, stats *store.StoreStats, watchlist []watchlistRow, sampleCount int64) workspaceSummary {
	healthy, alerts := 0, 0
	for i := range watchlist {
		if watchlist[i].Hysteresis == "2/2 alert" {
			alerts++
		} else if watchlist[i].Health == "OK" {
			healthy++
		}
	}
	var okTicks, totalTicks int64
	if cronStatus != nil {
		for i := range cronStatus.DailyStats {
			d := &cronStatus.DailyStats[i]
			okTicks += d.OKCount
			totalTicks += d.OKCount + d.WarnCount + d.FailCount
		}
	}
	var pct float64
	if totalTicks > 0 {
		pct = roundTo((float64(okTicks)/float64(totalTicks))*100, 1)
	} else if len(watchlist) > 0 {
		pct = roundTo((float64(healthy)/float64(len(watchlist)))*100, 1)
	}
	var maxStoreBytes, jobCount, dbSizeBytes, destCount int64
	if stats != nil {
		maxStoreBytes = stats.MaxStoreBytes
		jobCount = stats.JobCount
		dbSizeBytes = stats.DBSizeBytes
		destCount = stats.DestinationCount
	}
	archiveMaxMB := float64(store.DefaultMaxStoreMB)
	if maxStoreBytes > 0 {
		archiveMaxMB = roundTo(float64(maxStoreBytes)/bytesPerMiB, 2)
	}
	if sampleCount == 0 && totalTicks > 0 {
		sampleCount = totalTicks
	}
	return workspaceSummary{
		CronHealthPct: pct, HealthyTargets: healthy, TotalTargets: len(watchlist),
		ActiveAlerts: alerts, RetainedJobs: jobCount,
		ArchiveMB: roundTo(float64(dbSizeBytes)/bytesPerMiB, 2), ArchiveMaxMB: archiveMaxMB,
		SavedDestinations: int(destCount), SampleCount: sampleCount,
	}
}

func buildStripDays(daily []store.CronDailyStat) []stripDay {
	type agg struct {
		ok, warn, fail, total int64
		weighted              float64
	}
	byDay := make(map[string]*agg)
	for i := range daily {
		d := &daily[i]
		a := byDay[d.DayUTC]
		if a == nil {
			a = &agg{}
			byDay[d.DayUTC] = a
		}
		ticks := d.OKCount + d.WarnCount + d.FailCount
		a.ok, a.warn, a.fail, a.total = a.ok+d.OKCount, a.warn+d.WarnCount, a.fail+d.FailCount, a.total+ticks
		a.weighted += d.AvgDurationMS * float64(ticks)
	}
	days := make([]string, 0, len(byDay))
	for day := range byDay {
		days = append(days, day)
	}
	sort.Strings(days)
	strip := make([]stripDay, 0, len(days))
	for _, day := range days {
		a, status, avg := byDay[day], "OK", 0.0
		if a.fail > 0 {
			status = "FAIL"
		} else if a.warn > 0 {
			status = "WARN"
		}
		if a.total > 0 {
			avg = roundTo(a.weighted/float64(a.total), 2)
		}
		strip = append(strip, stripDay{Label: day, Status: status, AvgMs: avg, Detail: fmt.Sprintf("%d/%d ticks OK · avg %.1f ms", a.ok, a.total, avg)})
	}
	return strip
}

func buildWatchlistRows(items []cronmon.WatchItem, cronStatus *store.CronSummary, jobs []store.JobRecord) []watchlistRow {
	stateByKey := make(map[string]*store.CronStateRecord)
	dailyDur, jobDur := make(map[string]durAgg), make(map[string]durAgg)
	if cronStatus != nil {
		for i := range cronStatus.States {
			stateByKey[cronStatus.States[i].JobKey] = &cronStatus.States[i]
		}
		for i := range cronStatus.DailyStats {
			d := &cronStatus.DailyStats[i]
			ticks := d.OKCount + d.WarnCount + d.FailCount
			c := dailyDur[d.JobKey]
			c.sum += d.AvgDurationMS * float64(ticks)
			c.count += ticks
			dailyDur[d.JobKey] = c
		}
	}
	for i := range jobs {
		k, d := jobs[i].ToolName+"\x00"+jobs[i].Target, float64(jobs[i].DurationMS)
		c := jobDur[k]
		c.sum, c.count, c.max = c.sum+d, c.count+1, max(c.max, d)
		jobDur[k] = c
	}
	seen := make(map[string]struct{}, len(items)+len(stateByKey))
	rows := make([]watchlistRow, 0, len(items)+len(stateByKey))
	for i := range items {
		seen[items[i].Key] = struct{}{}
		rows = append(rows, makeWatchlistRow(items[i].Key, items[i].Target, items[i].Tool, stateByKey[items[i].Key], dailyDur, jobDur))
	}
	var extra []string
	for k := range stateByKey {
		if _, ok := seen[k]; !ok {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		st := stateByKey[k]
		rows = append(rows, makeWatchlistRow(st.JobKey, st.Target, st.ToolName, st, dailyDur, jobDur))
	}
	return rows
}

func makeWatchlistRow(key, target, tool string, st *store.CronStateRecord, dailyDur, jobDur map[string]durAgg) watchlistRow {
	health, hyst, lastTick := "OK", "0/2 clear", ""
	if st != nil {
		if s := strings.ToUpper(strings.TrimSpace(st.LastStatus)); s != "" {
			health = s
		}
		if st.ActiveAlert || st.ConsecutiveNonOK >= 2 {
			hyst = "2/2 alert"
		} else if st.ConsecutiveNonOK == 1 {
			hyst = "1/2 warn"
		}
		if st.LastTickAt > 0 {
			lastTick = time.Unix(st.LastTickAt, 0).UTC().Format(time.RFC3339)
		}
	}
	var avgMS, maxMS float64
	if a := dailyDur[key]; a.count > 0 {
		avgMS = roundTo(a.sum/float64(a.count), 2)
	}
	if a := jobDur[tool+"\x00"+target]; a.count > 0 {
		if avgMS == 0 {
			avgMS = roundTo(a.sum/float64(a.count), 2)
		}
		maxMS = roundTo(a.max, 2)
	}
	if maxMS == 0 && avgMS > 0 {
		maxMS = avgMS
	}
	return watchlistRow{Key: key, Target: target, Check: tool, Health: health, Hysteresis: hyst, AvgMS: avgMS, MaxMS: maxMS, LastTick: lastTick}
}

func toJobSummaryRows(jobs []store.JobRecord) []jobSummaryRow {
	rows := make([]jobSummaryRow, 0, len(jobs))
	for i := range jobs {
		j := &jobs[i]
		var created, expires string
		if j.CreatedAt > 0 {
			created = time.Unix(j.CreatedAt, 0).UTC().Format(time.RFC3339)
		}
		if j.ExpiresAt > 0 {
			expires = time.Unix(j.ExpiresAt, 0).UTC().Format(time.RFC3339)
		}
		rows = append(rows, jobSummaryRow{
			JobID: j.JobID, Tool: j.ToolName, Target: j.Target, Status: j.Status,
			Summary: j.Summary, CreatedAt: created, ExpiresAt: expires,
		})
	}
	return rows
}

func writeMappedError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, dispatch.ErrDeadboltLocked):
		writeJSON(w, http.StatusUnauthorized, map[string]any{"locked": true, "error": err.Error()})
	case errors.Is(err, cronmon.ErrItemNotFound), errors.Is(err, store.ErrNotFound), errors.Is(err, sql.ErrNoRows):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, dispatch.ErrUnknownTool), errors.Is(err, dispatch.ErrInvalidStyle),
		errors.Is(err, dispatch.ErrInvalidArgs), errors.Is(err, security.ErrTargetInvalid),
		errors.Is(err, security.ErrTargetDenied), errors.Is(err, security.ErrTargetNotAllowed),
		errors.Is(err, store.ErrInvalidPeriod), errors.Is(err, cronmon.ErrInvalidWatchlist),
		strings.Contains(err.Error(), "unsupported watchlist action"):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}
