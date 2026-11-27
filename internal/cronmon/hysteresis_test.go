package cronmon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatchlistValidationAndFileErrors(t *testing.T) {
	t.Parallel()

	_, err := LoadWatchlist("")
	require.ErrorIs(t, err, ErrInvalidWatchlist)

	_, err = LoadWatchlist(filepath.Join(t.TempDir(), "missing.yaml"))
	require.Error(t, err)

	require.ErrorIs(t, SaveWatchlist("", &WatchlistFile{Version: 1}), ErrInvalidWatchlist)
	require.ErrorIs(t, ValidateWatchlist(nil), ErrInvalidWatchlist)

	for _, tc := range []struct {
		name string
		wl   *WatchlistFile
	}{
		{name: "bad webhook", wl: &WatchlistFile{WebhookURL: "ftp://example.com/hook"}},
		{name: "empty key", wl: &WatchlistFile{Items: []WatchItem{{Schedule: "* * * * *", Tool: "ping"}}}},
		{name: "empty schedule", wl: &WatchlistFile{Items: []WatchItem{{Key: "k1", Tool: "ping"}}}},
		{name: "empty tool", wl: &WatchlistFile{Items: []WatchItem{{Key: "k1", Schedule: "* * * * *"}}}},
		{name: "neg timeout", wl: &WatchlistFile{Items: []WatchItem{{Key: "k1", Schedule: "* * * * *", Tool: "ping", TimeoutSeconds: -1}}}},
		{name: "dup key", wl: &WatchlistFile{Items: []WatchItem{
			{Key: "k1", Schedule: "* * * * *", Tool: "ping"},
			{Key: "k1", Schedule: "* * * * *", Tool: "ping"},
		}}},
		{name: "bad cron", wl: &WatchlistFile{Items: []WatchItem{{Key: "k1", Schedule: "not-cron", Tool: "ping"}}}},
	} {
		require.ErrorIs(t, ValidateWatchlist(tc.wl), ErrInvalidWatchlist, tc.name)
	}

	assert.Equal(t, &WatchlistFile{Version: 1}, cloneWatchlist(nil))
	cloned := cloneAnyMap(map[string]any{
		"nested": map[string]any{"a": 1},
		"slice":  []any{"x", "y"},
	})
	cloned["nested"].(map[string]any)["a"] = 2
	assert.Equal(t, 2, cloned["nested"].(map[string]any)["a"])
}

func TestManageWatchlistAndSchedulerGuards(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestJobStore(t)

	_, err := NewScheduler(nil)
	require.Error(t, err)

	runner := func(_ context.Context, item WatchItem) (*RunResult, error) {
		if item.Target == "fail.test" {
			return nil, errors.New("probe failed")
		}
		return &RunResult{Status: "HEALTHY", Summary: "", DurationMS: 5}, nil
	}

	sched := newTestScheduler(t, s, "", &WatchlistFile{
		Version: 1,
		Items:   []WatchItem{{Key: "k1", Schedule: "*/5 * * * *", Tool: "ping", Target: "1.1.1.1", Enabled: true}},
	}, runner, nil)

	require.Error(t, sched.Start(nil))
	require.NoError(t, sched.Start(ctx))
	require.NoError(t, sched.Start(ctx)) // idempotent start
	require.NoError(t, sched.Stop(nil))  // nil ctx defaults to Background

	// Start again after Stop recreates s.cron.
	require.NoError(t, sched.Start(ctx))
	require.NoError(t, sched.Stop(ctx))
	require.NoError(t, sched.Reload())

	_, err = sched.ManageWatchlist(nil, ManageParams{Action: "list"})
	require.Error(t, err)
	_, err = sched.ManageWatchlist(ctx, ManageParams{Action: "bogus"})
	require.Error(t, err)
	_, err = sched.ManageWatchlist(ctx, ManageParams{Action: "add", Key: "  "})
	require.ErrorIs(t, err, ErrInvalidWatchlist)
	_, err = sched.ManageWatchlist(ctx, ManageParams{Action: "add", Key: "k1", Schedule: "* * * * *", Tool: "ping"})
	require.ErrorIs(t, err, ErrInvalidWatchlist)
	_, err = sched.ManageWatchlist(ctx, ManageParams{Action: "remove", Key: "missing"})
	require.ErrorIs(t, err, ErrItemNotFound)

	// Update errors and valid partial updates (args, enabled, timeout).
	_, err = sched.ManageWatchlist(ctx, ManageParams{Action: "update", Key: "k1", Schedule: "bad"})
	require.ErrorIs(t, err, ErrInvalidWatchlist)
	_, err = sched.ManageWatchlist(ctx, ManageParams{Action: "update", Key: "k1", TimeoutSeconds: -5})
	require.ErrorIs(t, err, ErrInvalidWatchlist)

	disabled := false
	upd, err := sched.ManageWatchlist(ctx, ManageParams{
		Action: "update", Key: "k1", Tool: "http_ping", Target: "fail.test",
		Args: map[string]any{"count": 2}, Enabled: &disabled, TimeoutSeconds: 10,
	})
	require.NoError(t, err)
	assert.False(t, upd.Item.Enabled)
	assert.Equal(t, 10, upd.Item.TimeoutSeconds)

	// RunOnce & RunItemNow guards.
	require.Error(t, sched.RunOnce(nil))
	_, err = sched.RunItemNow(nil, "k1")
	require.Error(t, err)
	_, err = sched.RunItemNow(ctx, "  ")
	require.ErrorIs(t, err, ErrItemNotFound)
	_, err = sched.RunItemNow(ctx, "missing")
	require.ErrorIs(t, err, ErrItemNotFound)

	// Re-enable and verify RunOnce propagates runner error.
	_, err = sched.ManageWatchlist(ctx, ManageParams{Action: "resume", Key: "k1"})
	require.NoError(t, err)
	require.Error(t, sched.RunOnce(ctx))
}

func TestWebhookDispatchAndNormalizationAndStatusCard(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestJobStore(t)

	// Webhook syntax validation and HTTP error status handling.
	_, err := validateWebhookSyntax("://bad")
	require.Error(t, err)
	_, err = validateWebhookSyntax("ftp://hooks.example.test/a")
	require.Error(t, err)
	_, err = validateWebhookSyntax("https:///no-host")
	require.Error(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect-loop" {
			http.Redirect(w, r, "/redirect-loop", http.StatusFound)
			return
		}
		if r.URL.Path == "/redirect-meta" {
			http.Redirect(w, r, "http://169.254.169.254/latest", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	guard, err := security.NewTargetGuard([]string{"127.0.0.1/32"}, nil)
	require.NoError(t, err)

	sched := &Scheduler{
		store:      s,
		guard:      guard,
		httpClient: &http.Client{Timeout: 2 * time.Second, CheckRedirect: newDefaultHTTPClient(guard).CheckRedirect},
		watchlist:  &WatchlistFile{Version: 1},
	}

	require.Error(t, sched.dispatchWebhook(ctx, srv.URL, nil))
	st := &store.CronStateRecord{JobKey: "k1", ToolName: "ping", Target: "1.1.1.1", LastStatus: "FAIL"}
	err = sched.dispatchWebhook(ctx, srv.URL+"/err", st)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")

	err = sched.dispatchWebhook(ctx, srv.URL+"/redirect-loop", st)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirects")

	err = sched.dispatchWebhook(ctx, srv.URL+"/redirect-meta", st)
	require.Error(t, err)

	// Normalization variants.
	assert.Equal(t, "OK", normalizeCronStatus("PASS"))
	assert.Equal(t, "WARN", normalizeCronStatus("DEGRADED"))
	assert.Equal(t, "FAIL", normalizeCronStatus("UNKNOWN"))

	stNorm, sumNorm, _, _, durNorm := normalizeRunResult(nil, nil, 15)
	assert.Equal(t, "FAIL", stNorm)
	assert.Equal(t, "execution failed", sumNorm)
	assert.Equal(t, int64(15), durNorm)

	stNorm2, sumNorm2, _, _, _ := normalizeRunResult(&RunResult{Status: "OK"}, errors.New("boom"), 10)
	assert.Equal(t, "FAIL", stNorm2)
	assert.Equal(t, "boom", sumNorm2)

	// BuildCronStatusCard nil ctx, empty summary, and WARN/OK fallback health states.
	_, _, err = sched.BuildCronStatusCard(nil, "24h")
	require.Error(t, err)

	hStates, spark, ticks := buildDailyTrendData(nil)
	assert.Nil(t, hStates)
	assert.Nil(t, spark)
	assert.Equal(t, int64(0), ticks)

	_, _, err = s.RecordCronTick(ctx, "ok-only", "ping", "1.1.1.1", "OK", "j-ok", "", 0, time.Now().UTC())
	require.NoError(t, err)
	_, cardOK, err := sched.BuildCronStatusCard(ctx, "24h")
	require.NoError(t, err)
	assert.Equal(t, "OK", cardOK.Status)

	_, _, err = s.RecordCronTick(ctx, "warn-one", "ping", "1.1.1.1", "WARN", "j-w", "jitter", 0, time.Now().UTC())
	require.NoError(t, err)
	_, cardWarn, err := sched.BuildCronStatusCard(ctx, "24h")
	require.NoError(t, err)
	assert.Equal(t, "WARN", cardWarn.Status)
}
