package cronmon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/robfig/cron/v3"
)

// ManageParams defines inputs for ManageWatchlist operations.
type ManageParams struct {
	Action         string         `json:"action"`
	Key            string         `json:"key,omitempty"`
	Schedule       string         `json:"schedule,omitempty"`
	Tool           string         `json:"tool,omitempty"`
	Target         string         `json:"target,omitempty"`
	Args           map[string]any `json:"args,omitempty"`
	Enabled        *bool          `json:"enabled,omitempty"`
	TimeoutSeconds int            `json:"timeout_seconds,omitempty"`
}

// ManageResult reports the outcome of a ManageWatchlist call.
type ManageResult struct {
	Action string                 `json:"action"`
	Items  []WatchItem            `json:"items"`
	Item   *WatchItem             `json:"item,omitempty"`
	Tick   *store.CronStateRecord `json:"tick,omitempty"`
}

// WebhookPayload is posted as JSON when Two-Tick Alert Hysteresis flips state.
type WebhookPayload struct {
	Event            string `json:"event"`
	JobKey           string `json:"job_key"`
	Tool             string `json:"tool"`
	Target           string `json:"target"`
	Status           string `json:"status"`
	ActiveAlert      bool   `json:"active_alert"`
	ConsecutiveNonOK int    `json:"consecutive_non_ok"`
	JobID            string `json:"job_id"`
	Summary          string `json:"summary"`
	Timestamp        int64  `json:"timestamp"`
}

type dayBucketAgg struct {
	warnCount, failCount, totalTicks int64
	weightedDur                      float64
}

const (
	actionList              = "list"
	actionAdd               = "add"
	actionUpdate            = "update"
	actionRemove            = "remove"
	actionPause             = "pause"
	actionResume            = "resume"
	actionRunNow            = "run_now"
	maxWebhookBodyDrain     = 4096
	defaultHealthStripWidth = 24
)

// ManageWatchlist executes watchlist CRUD, pause/resume, or immediate run_now actions,
// persisting changes to WatchlistPath (when set) and hot-reloading active cron entries.
//
//nolint:gocritic // hugeParam: ManageParams value signature matches ManageWatchlist contract.
func (s *Scheduler) ManageWatchlist(ctx context.Context, params ManageParams) (*ManageResult, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}
	action := strings.ToLower(strings.TrimSpace(params.Action))
	switch action {
	case actionList:
		s.mu.RLock()
		items := cloneWatchItems(s.watchlist.Items)
		s.mu.RUnlock()
		return &ManageResult{Action: actionList, Items: items}, nil
	case actionRunNow:
		state, err := s.RunItemNow(ctx, params.Key)
		if err != nil {
			return nil, err
		}
		s.mu.RLock()
		items := cloneWatchItems(s.watchlist.Items)
		s.mu.RUnlock()
		var itemPtr *WatchItem
		if idx := findItemIndex(items, strings.TrimSpace(params.Key)); idx >= 0 {
			itemPtr = &items[idx]
		}
		return &ManageResult{Action: actionRunNow, Items: items, Item: itemPtr, Tick: &state}, nil
	case actionAdd, actionUpdate, actionRemove, actionPause, actionResume:
		params.Action = action
		return s.mutateWatchlist(&params)
	default:
		return nil, fmt.Errorf("unsupported watchlist action %q", params.Action)
	}
}

// BuildCronStatusCard queries SQLite cron rollups for period ("24h", "7d", or "30d")
// and formats an ascii.ReportCard with HealthStrip and Two-Tick Alert Hysteresis rows.
func (s *Scheduler) BuildCronStatusCard(ctx context.Context, period string) (*store.CronSummary, *ascii.ReportCard, error) {
	if ctx == nil {
		return nil, nil, errors.New("context must not be nil")
	}
	start := time.Now()
	summary, err := s.store.GetCronStatus(ctx, period)
	if err != nil {
		return nil, nil, fmt.Errorf("get cron status (%s): %w", period, err)
	}
	healthStates, sparkValues, totalTicks := buildDailyTrendData(summary)
	rows, activeAlerts, pendingWarn := buildCronRowsAndCounts(summary.States)
	if len(healthStates) == 0 && len(rows) > 0 {
		healthStates = make([]string, 0, len(rows))
		for i := range rows {
			healthStates = append(healthStates, rows[i].Status)
		}
	}
	overall, notes := cronStatusAndNotes(activeAlerts, pendingWarn, summary.States)
	card := &ascii.ReportCard{
		Title: "CRON WATCHLIST", Subtitle: summary.Period, ToolName: "get_cron_status",
		Status: overall, DurationMS: time.Since(start).Milliseconds(),
		Summary: fmt.Sprintf("%d checks tracked (%s): %d active alert(s), %d pending (1/2), %d ticks.",
			len(summary.States), summary.Period, activeAlerts, pendingWarn, totalTicks),
		HealthStates: healthStates, SparkValues: sparkValues,
		Metrics: []ascii.MetricKV{
			{Label: "Checks", Value: strconv.Itoa(len(summary.States))},
			{Label: "Alerts", Value: strconv.Itoa(activeAlerts)},
			{Label: "Pending", Value: strconv.Itoa(pendingWarn)},
			{Label: "Strip", Value: ascii.HealthStrip(healthStates, defaultHealthStripWidth)},
		},
		Headers: []string{"KEY", "TOOL", "TARGET", "HYST", "DETAIL"},
		Rows:    ascii.SortRowsBySeverity(rows),
		Notes:   notes,
	}
	return summary, card, nil
}

func (s *Scheduler) executeAndRecord(ctx context.Context, item *WatchItem) (store.CronStateRecord, error) {
	if ctx == nil || item == nil {
		return store.CronStateRecord{}, errors.New("context and watchlist item must not be nil")
	}
	timeout := defaultItemTimeout
	if item.TimeoutSeconds > 0 {
		timeout = time.Duration(item.TimeoutSeconds) * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	wallStart := time.Now()
	res, runErr := s.runner(runCtx, cloneWatchItem(item))
	wallMS := time.Since(wallStart).Milliseconds()
	cancel()
	if runErr != nil && ctx.Err() != nil {
		return store.CronStateRecord{}, fmt.Errorf("execute watchlist item %q: %w", item.Key, ctx.Err())
	}
	tickNow := time.Now().UTC()
	if s.nowFunc != nil {
		tickNow = s.nowFunc().UTC()
	}
	status, summary, asciiDefault, payloadJSON, durationMS := normalizeRunResult(res, runErr, wallMS)
	rec := &store.JobRecord{
		ToolName: item.Tool, Target: item.Target, Source: "cron", Status: status,
		Summary: summary, PayloadJSON: payloadJSON, ASCIIDefault: asciiDefault,
		DurationMS: durationMS, CreatedAt: tickNow.Unix(),
		ExpiresAt: tickNow.Add(store.DefaultRetention).Unix(), IsIncident: status != "OK",
	}
	if err := s.store.SaveJob(ctx, rec); err != nil {
		return store.CronStateRecord{}, fmt.Errorf("save cron job for %q: %w", item.Key, err)
	}
	state, alertFlipped, err := s.store.RecordCronTick(ctx, item.Key, item.Tool, item.Target, status, rec.JobID, summary, durationMS, tickNow)
	if err != nil {
		return store.CronStateRecord{}, fmt.Errorf("record cron tick for %q: %w", item.Key, err)
	}
	s.mu.RLock()
	webhookURL := strings.TrimSpace(s.watchlist.WebhookURL)
	s.mu.RUnlock()
	if alertFlipped && webhookURL != "" {
		_ = s.dispatchWebhook(ctx, webhookURL, &state)
	}
	if runErr != nil {
		return state, fmt.Errorf("run watchlist item %q (%s): %w", item.Key, item.Tool, runErr)
	}
	return state, nil
}

func (s *Scheduler) dispatchWebhook(ctx context.Context, rawURL string, state *store.CronStateRecord) error {
	if state == nil {
		return errors.New("cron state must not be nil")
	}
	parsedURL, err := validateWebhookSyntax(rawURL)
	if err != nil {
		return err
	}
	webhookCtx, cancel := context.WithTimeout(ctx, defaultWebhookTimeout)
	defer cancel()
	if _, err := s.guard.ValidateHostOrIP(webhookCtx, parsedURL.Hostname()); err != nil {
		return fmt.Errorf("webhook URL blocked by target guard: %w", err)
	}
	eventName := "alert_resolved"
	if state.ActiveAlert {
		eventName = "alert_triggered"
	}
	body, err := json.Marshal(WebhookPayload{
		Event: eventName, JobKey: state.JobKey, Tool: state.ToolName, Target: state.Target,
		Status: state.LastStatus, ActiveAlert: state.ActiveAlert, ConsecutiveNonOK: state.ConsecutiveNonOK,
		JobID: state.LastJobID, Summary: state.LastSummary, Timestamp: state.LastTickAt,
	})
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}
	// #nosec G107 -- webhook URL scheme and host are validated via TargetGuard above.
	req, err := http.NewRequestWithContext(webhookCtx, http.MethodPost, parsedURL.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mcp-adv-netutils/cronmon")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxWebhookBodyDrain))
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func newDefaultHTTPClient(guard *security.TargetGuard) *http.Client {
	return &http.Client{
		Timeout: defaultWebhookTimeout,
		Transport: &http.Transport{
			Proxy: nil, DialContext: guard.DialContext,
			DisableKeepAlives: true, IdleConnTimeout: defaultWebhookTimeout,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxWebhookRedirects {
				return fmt.Errorf("webhook stopped after %d redirects", maxWebhookRedirects)
			}
			host := req.URL.Hostname()
			if host == "" {
				return errors.New("webhook redirect URL missing host")
			}
			if _, err := guard.ValidateHostOrIP(req.Context(), host); err != nil {
				return fmt.Errorf("webhook redirect blocked by target guard: %w", err)
			}
			return nil
		},
	}
}

func validateWebhookSyntax(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("invalid webhook URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported webhook URL scheme %q", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return nil, errors.New("webhook URL missing host")
	}
	return parsed, nil
}

func (s *Scheduler) mutateWatchlist(params *ManageParams) (*ManageResult, error) {
	key := strings.TrimSpace(params.Key)
	if key == "" {
		return nil, fmt.Errorf("%w: key must not be empty", ErrInvalidWatchlist)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	nextWL := cloneWatchlist(s.watchlist)
	affected, hasAffected, err := applyWatchlistMutation(nextWL, key, params)
	if err != nil {
		return nil, err
	}
	if err := ValidateWatchlist(nextWL); err != nil {
		return nil, err
	}
	if s.watchlistPath != "" {
		if err := SaveWatchlist(s.watchlistPath, nextWL); err != nil {
			return nil, err
		}
	}
	prevWL := s.watchlist
	s.watchlist = nextWL
	if err := s.syncEntriesLocked(); err != nil {
		s.watchlist = prevWL
		return nil, err
	}
	res := &ManageResult{Action: params.Action, Items: cloneWatchItems(nextWL.Items)}
	if hasAffected {
		res.Item = &affected
	}
	return res, nil
}

func applyWatchlistMutation(nextWL *WatchlistFile, key string, params *ManageParams) (WatchItem, bool, error) {
	idx := findItemIndex(nextWL.Items, key)
	if params.Action == actionAdd {
		if idx >= 0 {
			return WatchItem{}, false, fmt.Errorf("%w: item %q already exists", ErrInvalidWatchlist, key)
		}
		added := WatchItem{
			Key: key, Schedule: strings.TrimSpace(params.Schedule), Tool: strings.TrimSpace(params.Tool),
			Target: strings.TrimSpace(params.Target), Args: cloneAnyMap(params.Args),
			Enabled: params.Enabled == nil || *params.Enabled, TimeoutSeconds: params.TimeoutSeconds,
		}
		nextWL.Items = append(nextWL.Items, added)
		return cloneWatchItem(&added), true, nil
	}
	if idx < 0 {
		return WatchItem{}, false, fmt.Errorf("%w: %q", ErrItemNotFound, key)
	}
	switch params.Action {
	case actionUpdate:
		if err := applyItemUpdate(&nextWL.Items[idx], params); err != nil {
			return WatchItem{}, false, err
		}
	case actionRemove:
		nextWL.Items = append(nextWL.Items[:idx], nextWL.Items[idx+1:]...)
		return WatchItem{}, false, nil
	case actionPause, actionResume:
		nextWL.Items[idx].Enabled = params.Action == actionResume
	default:
		return WatchItem{}, false, fmt.Errorf("unsupported watchlist action %q", params.Action)
	}
	return cloneWatchItem(&nextWL.Items[idx]), true, nil
}

func applyItemUpdate(item *WatchItem, params *ManageParams) error {
	if sched := strings.TrimSpace(params.Schedule); sched != "" {
		if _, err := cron.ParseStandard(sched); err != nil {
			return fmt.Errorf("%w: invalid schedule %q: %w", ErrInvalidWatchlist, sched, err)
		}
		item.Schedule = sched
	}
	if tool := strings.TrimSpace(params.Tool); tool != "" {
		item.Tool = tool
	}
	if target := strings.TrimSpace(params.Target); target != "" {
		item.Target = target
	}
	if params.Args != nil {
		item.Args = cloneAnyMap(params.Args)
	}
	if params.Enabled != nil {
		item.Enabled = *params.Enabled
	}
	if params.TimeoutSeconds < 0 {
		return fmt.Errorf("%w: timeout_seconds must be >= 0", ErrInvalidWatchlist)
	}
	if params.TimeoutSeconds > 0 {
		item.TimeoutSeconds = params.TimeoutSeconds
	}
	return nil
}

func findItemIndex(items []WatchItem, key string) int {
	for i := range items {
		if items[i].Key == key {
			return i
		}
	}
	return -1
}

func normalizeRunResult(res *RunResult, runErr error, wallMS int64) (string, string, string, string, int64) {
	if res == nil {
		summary := "execution failed"
		if runErr != nil {
			summary = runErr.Error()
		}
		return "FAIL", summary, "", "", wallMS
	}
	status, summary := normalizeCronStatus(res.Status), strings.TrimSpace(res.Summary)
	if runErr != nil {
		status = "FAIL"
		if summary == "" {
			summary = runErr.Error()
		}
	}
	if res.DurationMS > 0 {
		wallMS = res.DurationMS
	}
	return status, summary, res.ASCIIDefault, res.PayloadJSON, wallMS
}

func normalizeCronStatus(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "OK", "PASS", "UP", "HEALTHY":
		return "OK"
	case "WARN", "WARNING", "DEGRADED":
		return "WARN"
	default:
		return "FAIL"
	}
}

func buildDailyTrendData(summary *store.CronSummary) ([]string, []float64, int64) {
	if summary == nil || len(summary.DailyStats) == 0 {
		return nil, nil, 0
	}
	byDay := make(map[string]*dayBucketAgg)
	var totalTicks int64
	for i := range summary.DailyStats {
		d := &summary.DailyStats[i]
		agg := byDay[d.DayUTC]
		if agg == nil {
			agg = &dayBucketAgg{}
			byDay[d.DayUTC] = agg
		}
		ticks := d.OKCount + d.WarnCount + d.FailCount
		agg.warnCount += d.WarnCount
		agg.failCount += d.FailCount
		agg.weightedDur += d.AvgDurationMS * float64(ticks)
		agg.totalTicks += ticks
		totalTicks += ticks
	}
	days := slices.Sorted(maps.Keys(byDay))
	healthStates, sparkValues := make([]string, 0, len(days)), make([]float64, 0, len(days))
	for _, day := range days {
		agg, status, avg := byDay[day], "OK", 0.0
		switch {
		case agg.failCount > 0:
			status = "FAIL"
		case agg.warnCount > 0:
			status = "WARN"
		}
		if agg.totalTicks > 0 {
			avg = agg.weightedDur / float64(agg.totalTicks)
		}
		healthStates = append(healthStates, status)
		sparkValues = append(sparkValues, avg)
	}
	return healthStates, sparkValues, totalTicks
}

func buildCronRowsAndCounts(states []store.CronStateRecord) ([]ascii.TableRow, int, int) {
	rows := make([]ascii.TableRow, 0, len(states))
	activeAlerts, pendingWarn := 0, 0
	for i := range states {
		st := &states[i]
		rowStatus, hystBadge := "OK", "0/2 clear"
		switch {
		case st.ActiveAlert:
			rowStatus, hystBadge = "FAIL", strconv.Itoa(st.ConsecutiveNonOK)+"/2 alert"
			activeAlerts++
		case st.ConsecutiveNonOK > 0:
			rowStatus, hystBadge = "WARN", strconv.Itoa(st.ConsecutiveNonOK)+"/2 warn"
			pendingWarn++
		}
		detail := strings.TrimSpace(st.LastSummary)
		if detail == "" {
			detail = st.LastStatus
		}
		rows = append(rows, ascii.TableRow{Status: rowStatus, Cells: []string{st.JobKey, st.ToolName, st.Target, hystBadge, detail}})
	}
	return rows, activeAlerts, pendingWarn
}

func cronStatusAndNotes(activeAlerts, pendingWarn int, states []store.CronStateRecord) (string, []string) {
	status := "OK"
	switch {
	case activeAlerts > 0:
		status = "FAIL"
	case pendingWarn > 0:
		status = "WARN"
	default:
		for i := range states {
			if normalizeCronStatus(states[i].LastStatus) != "OK" {
				status = "WARN"
				break
			}
		}
	}
	notes := []string{"Two-Tick Alert Hysteresis: alerts trigger only at >= 2 consecutive non-OK ticks."}
	for i := range states {
		st := &states[i]
		if st.ActiveAlert || st.ConsecutiveNonOK > 0 {
			notes = append(notes, fmt.Sprintf("%s last_job_id=%s status=%s (%d consecutive)",
				st.JobKey, st.LastJobID, st.LastStatus, st.ConsecutiveNonOK))
		}
	}
	return status, notes
}
