package cronmon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openTestJobStore(t *testing.T) *store.JobStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "cronmon-test.db")
	s, err := store.Open(context.Background(), dbPath, 64)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}

func newTestScheduler(
	t *testing.T, s *store.JobStore, wlPath string, wl *WatchlistFile, runner RunnerFunc, nowFn func() time.Time,
) *Scheduler {
	t.Helper()
	sched, err := NewScheduler(&SchedulerConfig{
		Store: s, WatchlistPath: wlPath, Watchlist: wl, Runner: runner, NowFunc: nowFn,
	})
	require.NoError(t, err)
	return sched
}

func TestLoadSaveWatchlistAndValidation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	wlPath := filepath.Join(dir, "nested", "watchlist.yaml")
	want := &WatchlistFile{
		Version:    1,
		WebhookURL: "https://hooks.example.test/alerts",
		Items: []WatchItem{
			{
				Key: "wan-canary", Schedule: "*/5 * * * *", Tool: "recipe_diff_ping", Target: "1.1.1.1",
				Args: map[string]any{"count": 3}, Enabled: true, TimeoutSeconds: 15,
			},
			{Key: "nightly-tls", Schedule: "0 3 * * *", Tool: "tls_certificate_check", Target: "example.com"},
		},
	}

	require.NoError(t, SaveWatchlist(wlPath, want))
	info, err := os.Stat(wlPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	got, err := LoadWatchlist(wlPath)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	legacyPath := filepath.Join(dir, "legacy.yaml")
	legacyYAML := "jobs:\n  - id: legacy-ping\n    schedule: \"*/5 * * * *\"\n    tool: recipe_diff_ping\n    target: \"1.1.1.1\"\n    enabled: true\n"
	require.NoError(t, os.WriteFile(legacyPath, []byte(legacyYAML), 0o600))
	legacyWL, err := LoadWatchlist(legacyPath)
	require.NoError(t, err)
	require.Len(t, legacyWL.Items, 1)
	assert.Equal(t, "legacy-ping", legacyWL.Items[0].Key)
	assert.True(t, legacyWL.Items[0].Enabled)

	invalid := []*WatchlistFile{
		{Version: 1, Items: []WatchItem{{Key: "bad", Schedule: "not a cron", Tool: "ping", Target: "1.1.1.1", Enabled: true}}},
		{Version: 1, Items: []WatchItem{{Key: "short", Schedule: "* * *", Tool: "ping", Target: "1.1.1.1", Enabled: true}}},
		{Version: 1, Items: []WatchItem{{Key: "six", Schedule: "0 */5 * * * *", Tool: "ping", Target: "1.1.1.1", Enabled: true}}},
		{Version: 1, Items: []WatchItem{
			{Key: "dup", Schedule: "*/5 * * * *", Tool: "ping", Target: "1.1.1.1", Enabled: true},
			{Key: "dup", Schedule: "*/10 * * * *", Tool: "ping", Target: "8.8.8.8", Enabled: true},
		}},
		{Version: 1, WebhookURL: "ftp://hooks.example.test/alert", Items: []WatchItem{
			{Key: "ok", Schedule: "*/5 * * * *", Tool: "ping", Target: "1.1.1.1", Enabled: true},
		}},
	}
	for _, wl := range invalid {
		require.Error(t, SaveWatchlist(filepath.Join(dir, "bad.yaml"), wl))
	}

	badDiskPath := filepath.Join(dir, "bad-disk.yaml")
	require.NoError(t, os.WriteFile(badDiskPath, []byte("items:\n  - key: bad\n    schedule: '99 * * * *'\n    tool: ping\n"), 0o600))
	_, err = LoadWatchlist(badDiskPath)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidWatchlist)
}

func TestRunOnceBoundedConcurrencyAndDisabledSkip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := openTestJobStore(t)
	fixedNow := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	wl := &WatchlistFile{
		Version: 1,
		Items: []WatchItem{
			{Key: "k1", Schedule: "*/5 * * * *", Tool: "ping", Target: "192.0.2.1", Enabled: true},
			{Key: "k2", Schedule: "*/5 * * * *", Tool: "ping", Target: "192.0.2.2", Enabled: true},
			{Key: "k3", Schedule: "*/5 * * * *", Tool: "ping", Target: "192.0.2.3", Enabled: true},
			{Key: "k4", Schedule: "*/5 * * * *", Tool: "ping", Target: "192.0.2.4", Enabled: true},
			{Key: "k5", Schedule: "*/5 * * * *", Tool: "ping", Target: "192.0.2.5", Enabled: true},
			{Key: "k6-disabled", Schedule: "*/5 * * * *", Tool: "ping", Target: "192.0.2.6", Enabled: false},
		},
	}

	var active, peak atomic.Int32
	var ranMu sync.Mutex
	ranKeys := make(map[string]int)

	runner := func(_ context.Context, item WatchItem) (*RunResult, error) {
		cur := active.Add(1)
		for prev := peak.Load(); cur > prev && !peak.CompareAndSwap(prev, cur); prev = peak.Load() {
		}
		time.Sleep(15 * time.Millisecond)
		active.Add(-1)

		ranMu.Lock()
		ranKeys[item.Key]++
		ranMu.Unlock()
		return &RunResult{
			Status: "OK", Summary: "ok " + item.Target, ASCIIDefault: "[OK] " + item.Key,
			PayloadJSON: `{"ok":true}`, DurationMS: 15,
		}, nil
	}

	sched := newTestScheduler(t, s, "", wl, runner, func() time.Time { return fixedNow })
	require.NoError(t, sched.RunOnce(ctx))

	assert.LessOrEqual(t, peak.Load(), int32(runOnceConcurrency))
	assert.Len(t, ranKeys, 5)
	assert.Zero(t, ranKeys["k6-disabled"])

	jobs, err := s.ListJobs(ctx, store.JobFilter{Source: "cron"})
	require.NoError(t, err)
	require.Len(t, jobs, 5)
	for _, job := range jobs {
		assert.Equal(t, "cron", job.Source)
		assert.False(t, job.IsIncident)
		assert.Equal(t, fixedNow.Add(store.DefaultRetention).Unix(), job.ExpiresAt)
	}
}

func newWebhookRecorder(t *testing.T) (*httptest.Server, func() []WebhookPayload) {
	t.Helper()
	var mu sync.Mutex
	var got []WebhookPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		var p WebhookPayload
		require.NoError(t, json.NewDecoder(r.Body).Decode(&p))
		mu.Lock()
		got = append(got, p)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []WebhookPayload {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]WebhookPayload, len(got))
		copy(cp, got)
		return cp
	}
}

func TestTwoTickAlertHysteresisAndWebhookGuard(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := openTestJobStore(t)
	srv, webhooks := newWebhookRecorder(t)

	var stateMu sync.Mutex
	curStatus, curSummary := "FAIL", "packet loss 100%"
	curTime := time.Date(2026, 11, 26, 15, 0, 0, 0, time.UTC)
	wl := &WatchlistFile{
		Version: 1, WebhookURL: srv.URL,
		Items: []WatchItem{{Key: "wan-canary", Schedule: "*/5 * * * *", Tool: "recipe_diff_ping", Target: "1.1.1.1", Enabled: true, TimeoutSeconds: 10}},
	}
	runner := func(_ context.Context, _ WatchItem) (*RunResult, error) {
		stateMu.Lock()
		st, sum := curStatus, curSummary
		stateMu.Unlock()
		return &RunResult{Status: st, Summary: sum, PayloadJSON: `{"status":"` + st + `"}`, DurationMS: 25}, nil
	}
	sched := newTestScheduler(t, s, "", wl, runner, func() time.Time {
		stateMu.Lock()
		defer stateMu.Unlock()
		return curTime
	})
	tick := func(status, summary string) store.CronStateRecord {
		stateMu.Lock()
		curStatus, curSummary, curTime = status, summary, curTime.Add(5*time.Minute)
		stateMu.Unlock()
		st, err := sched.RunItemNow(ctx, "wan-canary")
		require.NoError(t, err)
		return st
	}

	// 1st FAIL tick -> ActiveAlert=false, 0 webhooks; JobRecord stored with 30d TTL.
	st1 := tick("FAIL", "packet loss 100%")
	assert.False(t, st1.ActiveAlert)
	assert.Equal(t, 1, st1.ConsecutiveNonOK)
	assert.Empty(t, webhooks())
	job1, err := s.GetJob(ctx, st1.LastJobID)
	require.NoError(t, err)
	assert.Equal(t, "cron", job1.Source)
	assert.True(t, job1.IsIncident)
	assert.Equal(t, curTime.Add(store.DefaultRetention).Unix(), job1.ExpiresAt)

	// 2nd consecutive FAIL tick -> ActiveAlert=true, 1 webhook sent.
	st2 := tick("FAIL", "packet loss 100%")
	assert.True(t, st2.ActiveAlert)
	assert.Equal(t, 2, st2.ConsecutiveNonOK)
	require.Len(t, webhooks(), 1)
	assert.Equal(t, "alert_triggered", webhooks()[0].Event)
	assert.True(t, webhooks()[0].ActiveAlert)

	// 3rd consecutive FAIL tick -> stays active, no duplicate alert webhook.
	st3 := tick("FAIL", "packet loss 100%")
	assert.True(t, st3.ActiveAlert)
	assert.Len(t, webhooks(), 1)

	// 1st OK tick -> clears alert and sends recovery notification.
	st4 := tick("OK", "0% loss in 12ms")
	assert.False(t, st4.ActiveAlert)
	assert.Equal(t, 0, st4.ConsecutiveNonOK)
	require.Len(t, webhooks(), 2)
	assert.Equal(t, "alert_resolved", webhooks()[1].Event)
	assert.False(t, webhooks()[1].ActiveAlert)

	metaErr := sched.dispatchWebhook(ctx, "http://169.254.169.254/latest/meta-data", &st2)
	require.Error(t, metaErr)
	assert.ErrorIs(t, metaErr, security.ErrTargetDenied)
}

func TestManageWatchlistLifecycleAndHotReload(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := openTestJobStore(t)
	wlPath := filepath.Join(t.TempDir(), "watchlist.yaml")
	require.NoError(t, SaveWatchlist(wlPath, &WatchlistFile{
		Version: 1,
		Items:   []WatchItem{{Key: "gw-ping", Schedule: "*/5 * * * *", Tool: "ping", Target: "192.0.2.1", Enabled: true}},
	}))

	var runMu sync.Mutex
	runs := make(map[string]int)
	runner := func(_ context.Context, item WatchItem) (*RunResult, error) {
		runMu.Lock()
		runs[item.Key]++
		runMu.Unlock()
		return &RunResult{Status: "OK", Summary: "ok " + item.Key, DurationMS: 8}, nil
	}

	sched := newTestScheduler(t, s, wlPath, nil, runner, nil)
	require.NoError(t, sched.Start(ctx))
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		require.NoError(t, sched.Stop(stopCtx))
	}()

	listed, err := sched.ManageWatchlist(ctx, ManageParams{Action: "list"})
	require.NoError(t, err)
	require.Len(t, listed.Items, 1)

	added, err := sched.ManageWatchlist(ctx, ManageParams{
		Action: "add", Key: "dns-diff", Schedule: "0 */6 * * *", Tool: "recipe_diff_dns",
		Target: "example.com", Args: map[string]any{"record_type": "A"}, TimeoutSeconds: 20,
	})
	require.NoError(t, err)
	require.Len(t, added.Items, 2)
	assert.Len(t, sched.cron.Entries(), 2)

	_, err = sched.ManageWatchlist(ctx, ManageParams{
		Action: "add", Key: "bad", Schedule: "bad-expr", Tool: "ping", Target: "1.1.1.1",
	})
	require.Error(t, err)
	assert.Len(t, sched.cron.Entries(), 2)

	updated, err := sched.ManageWatchlist(ctx, ManageParams{
		Action: "update", Key: "dns-diff", Schedule: "*/15 * * * *", Target: "example.org",
	})
	require.NoError(t, err)
	require.NotNil(t, updated.Item)
	assert.Equal(t, "example.org", updated.Item.Target)

	paused, err := sched.ManageWatchlist(ctx, ManageParams{Action: "pause", Key: "dns-diff"})
	require.NoError(t, err)
	require.NotNil(t, paused.Item)
	assert.False(t, paused.Item.Enabled)
	assert.Len(t, sched.cron.Entries(), 1)

	require.NoError(t, sched.RunOnce(ctx))
	runMu.Lock()
	assert.Equal(t, 1, runs["gw-ping"])
	assert.Equal(t, 0, runs["dns-diff"])
	runMu.Unlock()

	resumed, err := sched.ManageWatchlist(ctx, ManageParams{Action: "resume", Key: "dns-diff"})
	require.NoError(t, err)
	require.NotNil(t, resumed.Item)
	assert.True(t, resumed.Item.Enabled)
	assert.Len(t, sched.cron.Entries(), 2)

	ranNow, err := sched.ManageWatchlist(ctx, ManageParams{Action: "run_now", Key: "dns-diff"})
	require.NoError(t, err)
	require.NotNil(t, ranNow.Tick)
	assert.Equal(t, "OK", ranNow.Tick.LastStatus)

	removed, err := sched.ManageWatchlist(ctx, ManageParams{Action: "remove", Key: "dns-diff"})
	require.NoError(t, err)
	require.Len(t, removed.Items, 1)
	assert.Len(t, sched.cron.Entries(), 1)

	diskWL, err := LoadWatchlist(wlPath)
	require.NoError(t, err)
	require.Len(t, diskWL.Items, 1)

	diskWL.Items = append(diskWL.Items, WatchItem{
		Key: "reloaded-http", Schedule: "@every 1m", Tool: "http_ping", Target: "https://example.com", Enabled: true,
	})
	require.NoError(t, SaveWatchlist(wlPath, diskWL))
	require.NoError(t, sched.Reload())
	assert.Len(t, sched.cron.Entries(), 2)
}

func TestBuildCronStatusCardAllPeriods(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := openTestJobStore(t)
	now := time.Now().UTC()

	oldDay := now.Add(-10 * 24 * time.Hour)
	_, _, err := s.RecordCronTick(ctx, "gw-ping", "ping", "192.0.2.1", "OK", "old_seed", "healthy", 10, oldDay)
	require.NoError(t, err)
	require.NoError(t, s.SaveJob(ctx, &store.JobRecord{
		JobID: "old_ok_1", ToolName: "ping", Target: "192.0.2.1", Source: "cron",
		Status: "OK", DurationMS: 12, CreatedAt: oldDay.Unix(),
	}))
	compacted, err := s.DownAgeHealthyTicks(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, int64(1), compacted)

	require.NoError(t, s.SaveJob(ctx, &store.JobRecord{
		JobID: "recent_3d", ToolName: "ping", Target: "192.0.2.1", Source: "cron",
		Status: "OK", DurationMS: 14, CreatedAt: now.Add(-3 * 24 * time.Hour).Unix(),
	}))

	statuses := map[string]string{"gw-ping": "OK", "dns-warn": "WARN", "wan-fail": "FAIL"}
	wl := &WatchlistFile{
		Version: 1,
		Items: []WatchItem{
			{Key: "gw-ping", Schedule: "*/5 * * * *", Tool: "ping", Target: "192.0.2.1", Enabled: true},
			{Key: "dns-warn", Schedule: "*/5 * * * *", Tool: "recipe_diff_dns", Target: "example.com", Enabled: true},
			{Key: "wan-fail", Schedule: "*/5 * * * *", Tool: "recipe_diff_ping", Target: "1.1.1.1", Enabled: true},
		},
	}
	runner := func(_ context.Context, item WatchItem) (*RunResult, error) {
		return &RunResult{Status: statuses[item.Key], Summary: item.Key + " " + statuses[item.Key], DurationMS: 18}, nil
	}

	sched := newTestScheduler(t, s, "", wl, runner, func() time.Time { return now })
	for _, key := range []string{"gw-ping", "dns-warn", "wan-fail", "wan-fail"} {
		_, runErr := sched.RunItemNow(ctx, key)
		require.NoError(t, runErr)
	}

	for _, period := range []string{"24h", "7d", "30d"} {
		summary, card, cardErr := sched.BuildCronStatusCard(ctx, period)
		require.NoError(t, cardErr)
		require.NotNil(t, summary)
		require.NotNil(t, card)
		assert.Equal(t, period, summary.Period)
		assert.Equal(t, "FAIL", card.Status)
		assert.NotEmpty(t, card.HealthStates)
		require.Len(t, card.Rows, 3)
		assert.Equal(t, "2/2 alert", card.Rows[0].Cells[3])
		assert.Equal(t, "1/2 warn", card.Rows[1].Cells[3])
		assert.Equal(t, "0/2 clear", card.Rows[2].Cells[3])

		for _, style := range []string{ascii.StyleDefault, ascii.StyleQuick, ascii.StyleRich, ascii.StyleJSON} {
			rendered, renderErr := ascii.Render(card, style)
			require.NoError(t, renderErr)
			assert.NotEmpty(t, rendered)
			if style == ascii.StyleQuick {
				for _, line := range strings.Split(rendered, "\n") {
					assert.LessOrEqual(t, ascii.RuneLen(line), 40)
				}
			}
			if style == ascii.StyleJSON {
				assert.Less(t, len(rendered), ascii.MaxJSONBytes)
			}
		}
	}

	_, _, err = sched.BuildCronStatusCard(ctx, "99d")
	require.Error(t, err)
	assert.ErrorIs(t, err, store.ErrInvalidPeriod)
}

func TestSchedulerCronTickerAndRestart(t *testing.T) {
	t.Parallel()

	s := openTestJobStore(t)
	var hits atomic.Int32
	wl := &WatchlistFile{
		Version: 1,
		Items:   []WatchItem{{Key: "fast-tick", Schedule: "@every 1s", Tool: "ping", Target: "127.0.0.1", Enabled: true}},
	}
	runner := func(_ context.Context, _ WatchItem) (*RunResult, error) {
		hits.Add(1)
		return &RunResult{Status: "OK", Summary: "pong", DurationMS: 2}, nil
	}

	sched := newTestScheduler(t, s, "", wl, runner, nil)
	require.NoError(t, sched.Start(context.Background()))
	require.Eventually(t, func() bool { return hits.Load() >= 1 }, 3*time.Second, 25*time.Millisecond)

	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, sched.Stop(stopCtx))

	runCtx, runCancel := context.WithCancel(context.Background())
	require.NoError(t, sched.Start(runCtx))
	runCancel()
	require.NoError(t, sched.Stop(context.Background()))
}
