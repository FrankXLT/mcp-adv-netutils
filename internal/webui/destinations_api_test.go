package webui_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/cronmon"
	"github.com/FrankXLT/mcp-adv-netutils/internal/dispatch"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/FrankXLT/mcp-adv-netutils/internal/webui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDestinationsDeadboltEnforcement(t *testing.T) {
	t.Parallel()
	deps := newTestStudio(t, "alpha bravo charlie")

	for _, tc := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/api/destinations", ""},
		{http.MethodPost, "/api/destinations", `{"name":"GW","target":"127.0.0.1"}`},
		{http.MethodPut, "/api/destinations/dest-1", `{"name":"GW","target":"127.0.0.1"}`},
		{http.MethodDelete, "/api/destinations/dest-1", ""},
		{http.MethodPost, "/api/destinations/dest-1/run", `{}`},
		{http.MethodPost, "/api/scan-pinned", `{}`},
	} {
		rr := doReq(t, deps.handler, tc.method, tc.path, tc.body)
		assert.Equal(t, http.StatusUnauthorized, rr.Code, "%s %s", tc.method, tc.path)
		assert.Equal(t, map[string]any{"locked": true, "error": "operator studio locked"}, decodeMap(t, rr))
	}

	unlock := doReq(t, deps.handler, http.MethodPost, "/api/unlock", `{"passphrase":"alpha bravo charlie"}`)
	require.Equal(t, http.StatusOK, unlock.Code)
	cookie := findCookie(t, unlock, "netutils_session")
	require.NotNil(t, cookie)

	listOK := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/destinations", "", []*http.Cookie{cookie})
	require.Equal(t, http.StatusOK, listOK.Code)
	assert.Equal(t, []any{}, decodeMap(t, listOK)["destinations"])
}

func TestDestinationsCRUDValidationAndMonitorSync(t *testing.T) {
	t.Parallel()
	deps := newTestStudio(t, "")

	// Empty list returns [] (not null).
	emptyList := doReq(t, deps.handler, http.MethodGet, "/api/destinations", "")
	require.Equal(t, http.StatusOK, emptyList.Code)
	assert.Equal(t, []any{}, decodeMap(t, emptyList)["destinations"])

	// Validation errors -> 400 Bad Request.
	missingFields := doReq(t, deps.handler, http.MethodPost, "/api/destinations", `{"name":"OnlyName"}`)
	assert.Equal(t, http.StatusBadRequest, missingFields.Code)

	ssrfBlocked := doReq(t, deps.handler, http.MethodPost, "/api/destinations", `{"name":"Meta","target":"169.254.169.254"}`)
	assert.Equal(t, http.StatusBadRequest, ssrfBlocked.Code)

	badCheck := doReq(t, deps.handler, http.MethodPost, "/api/destinations", `{"name":"BadCheck","target":"127.0.0.1","default_check":"unlock_netutils"}`)
	assert.Equal(t, http.StatusBadRequest, badCheck.Code)

	// 404 on unknown IDs.
	delMissing := doReq(t, deps.handler, http.MethodDelete, "/api/destinations/dest-does-not-exist", "")
	assert.Equal(t, http.StatusNotFound, delMissing.Code)

	runMissing := doReq(t, deps.handler, http.MethodPost, "/api/destinations/dest-does-not-exist/run", `{}`)
	assert.Equal(t, http.StatusNotFound, runMissing.Code)

	// Create with monitor_enabled=true and verify cron scheduler sync.
	createResp := doReq(t, deps.handler, http.MethodPost, "/api/destinations", `{
		"name":"Core Switch","target":"192.0.2.10","category":"Core",
		"mac":"00:00:5E:00:53:10","default_check":"mac_vendor_lookup",
		"pinned":true,"monitor_enabled":true,"monitor_schedule":"*/10 * * * *"
	}`)
	require.Equal(t, http.StatusOK, createResp.Code, "body=%s", createResp.Body.String())
	var saved struct {
		Item         store.SavedDestination   `json:"item"`
		Destinations []store.SavedDestination `json:"destinations"`
	}
	require.NoError(t, json.Unmarshal(createResp.Body.Bytes(), &saved))
	require.NotEmpty(t, saved.Item.ID)
	assert.Equal(t, "Core Switch", saved.Item.Name)
	assert.True(t, saved.Item.Pinned)
	assert.True(t, saved.Item.MonitorEnabled)
	require.Len(t, saved.Destinations, 1)

	cronKey := "dest_" + saved.Item.ID
	assertWatchlistHasKey(t, deps.handler, cronKey, true)

	// PUT updates fields and toggles monitor_enabled=false, removing cron entry.
	putResp := doReq(t, deps.handler, http.MethodPut, "/api/destinations/"+saved.Item.ID, `{
		"name":"Core Switch Updated","pinned":false,"monitor_enabled":false
	}`)
	require.Equal(t, http.StatusOK, putResp.Code, "body=%s", putResp.Body.String())
	var updated struct {
		Item         store.SavedDestination   `json:"item"`
		Destinations []store.SavedDestination `json:"destinations"`
	}
	require.NoError(t, json.Unmarshal(putResp.Body.Bytes(), &updated))
	assert.Equal(t, saved.Item.ID, updated.Item.ID)
	assert.Equal(t, "Core Switch Updated", updated.Item.Name)
	assert.Equal(t, "00:00:5E:00:53:10", updated.Item.MAC)
	assert.False(t, updated.Item.Pinned)
	assert.False(t, updated.Item.MonitorEnabled)
	assertWatchlistHasKey(t, deps.handler, cronKey, false)

	// PUT with explicit "mac": "" clears MAC.
	clearMAC := doReq(t, deps.handler, http.MethodPut, "/api/destinations/"+saved.Item.ID, `{"mac":""}`)
	require.Equal(t, http.StatusOK, clearMAC.Code)
	var cleared struct {
		Item store.SavedDestination `json:"item"`
	}
	require.NoError(t, json.Unmarshal(clearMAC.Body.Bytes(), &cleared))
	assert.Empty(t, cleared.Item.MAC)

	// PUT toggling monitor_enabled=true re-adds cron entry.
	reEnable := doReq(t, deps.handler, http.MethodPut, "/api/destinations/"+saved.Item.ID, `{"monitor_enabled":true}`)
	require.Equal(t, http.StatusOK, reEnable.Code)
	assertWatchlistHasKey(t, deps.handler, cronKey, true)

	// DELETE removes destination and cleans up cron watchlist entry.
	delOK := doReq(t, deps.handler, http.MethodDelete, "/api/destinations/"+saved.Item.ID, "")
	require.Equal(t, http.StatusOK, delOK.Code)
	assert.Equal(t, []any{}, decodeMap(t, delOK)["destinations"])
	assertWatchlistHasKey(t, deps.handler, cronKey, false)
}

func TestDestinationRunAndScanPinned(t *testing.T) {
	t.Parallel()
	deps := newTestStudio(t, "")

	// Empty pinned sweep returns count=0 and empty array.
	emptySweep := doReq(t, deps.handler, http.MethodPost, "/api/scan-pinned", `{}`)
	require.Equal(t, http.StatusOK, emptySweep.Code)
	assert.Equal(t, float64(0), decodeMap(t, emptySweep)["count"])
	assert.Equal(t, []any{}, decodeMap(t, emptySweep)["results"])

	// Create 2 pinned and 1 unpinned destination.
	id1 := mustCreateDest(t, deps.handler, `{"name":"Pinned-1","target":"192.0.2.10","mac":"00:00:5E:00:53:10","default_check":"mac_vendor_lookup","pinned":true}`)
	_ = mustCreateDest(t, deps.handler, `{"name":"Pinned-2","target":"192.0.2.11","mac":"00:00:5E:00:53:11","default_check":"mac_vendor_lookup","pinned":true}`)
	_ = mustCreateDest(t, deps.handler, `{"name":"Unpinned-3","target":"192.0.2.12","mac":"00:00:5E:00:53:12","default_check":"mac_vendor_lookup","pinned":false}`)

	// Single destination run with empty body defaults cleanly.
	runResp := doReq(t, deps.handler, http.MethodPost, "/api/destinations/"+id1+"/run", "")
	require.Equal(t, http.StatusOK, runResp.Code, "body=%s", runResp.Body.String())
	runOut := decodeMap(t, runResp)
	assert.Equal(t, "mac_vendor_lookup", runOut["tool"])
	assert.Equal(t, "OK", runOut["status"])
	assert.Equal(t, "json", runOut["style"])

	// Batch sweep runs only the 2 pinned destinations.
	sweepResp := doReq(t, deps.handler, http.MethodPost, "/api/scan-pinned", `{"style":"quick"}`)
	require.Equal(t, http.StatusOK, sweepResp.Code, "body=%s", sweepResp.Body.String())
	var sweep struct {
		Count   int `json:"count"`
		Results []struct {
			Destination store.SavedDestination `json:"destination"`
			Outcome     *dispatch.Outcome      `json:"outcome"`
			Error       string                 `json:"error"`
		} `json:"results"`
	}
	require.NoError(t, json.Unmarshal(sweepResp.Body.Bytes(), &sweep))
	assert.Equal(t, 2, sweep.Count)
	require.Len(t, sweep.Results, 2)
	for _, r := range sweep.Results {
		assert.True(t, r.Destination.Pinned)
		assert.Empty(t, r.Error)
		require.NotNil(t, r.Outcome)
		assert.Equal(t, "OK", r.Outcome.Status)
		assert.Equal(t, "quick", r.Outcome.Style)
	}
}

func TestCronTimeseriesSummaryAndLockedRedaction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, err := store.Open(ctx, ":memory:", 16)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)

	db := security.NewDeadbolt(security.DeadboltConfig{
		PassHash:               security.NormalizePhrase("victor uniform"),
		TTL:                    5 * time.Minute,
		AllowLockedCronSummary: true,
	})
	wl := &cronmon.WatchlistFile{
		Version: 1,
		Items: []cronmon.WatchItem{
			{Key: "secret-gw", Schedule: "*/5 * * * *", Tool: "ping", Target: "secret-internal.corp.example", Enabled: true},
		},
	}
	sched, err := cronmon.NewScheduler(&cronmon.SchedulerConfig{
		Store: st, Watchlist: wl, Guard: guard,
		Runner: func(_ context.Context, _ cronmon.WatchItem) (*cronmon.RunResult, error) {
			return &cronmon.RunResult{Status: "OK", DurationMS: 10}, nil
		},
	})
	require.NoError(t, err)
	disp, err := dispatch.New(dispatch.Config{
		Version: "1.0-test", Deadbolt: db, Guard: guard, Store: st, Scheduler: sched, AllowLockedCronSummary: true,
	})
	require.NoError(t, err)
	h, err := webui.NewHandler(webui.Config{
		Version: "1.0-test", Dispatcher: disp, Store: st, Scheduler: sched, Deadbolt: db, AllowLockedCronSummary: true,
	})
	require.NoError(t, err)

	// Seed 1 saved destination and 2 jobs in the last 24h.
	require.NoError(t, st.SaveDestination(ctx, &store.SavedDestination{
		Name: "Hidden Host", Target: "hidden.internal.example", DefaultCheck: "ping",
	}))
	now := time.Now().UTC()
	require.NoError(t, st.SaveJob(ctx, &store.JobRecord{
		JobID: "ts-1", ToolName: "ping", Target: "secret-internal.corp.example", Source: "cron",
		Status: "OK", Summary: "ok", DurationMS: 10, CreatedAt: now.Add(-2 * time.Hour).Unix(),
	}))
	require.NoError(t, st.SaveJob(ctx, &store.JobRecord{
		JobID: "ts-2", ToolName: "ping", Target: "secret-internal.corp.example", Source: "cron",
		Status: "WARN", Summary: "slow", DurationMS: 50, CreatedAt: now.Add(-10 * time.Minute).Unix(), IsIncident: true,
	}))

	// Invalid range returns 400.
	badRange := doReq(t, h, http.MethodGet, "/api/cron?range=99d", "")
	assert.Equal(t, http.StatusBadRequest, badRange.Code)

	// While locked with AllowLockedCronSummary=true, /api/cron returns aggregates + timeseries without leaking hostnames.
	for _, rng := range []string{"24h", "7d", "30d"} {
		rr := doReq(t, h, http.MethodGet, "/api/cron?range="+rng, "")
		require.Equal(t, http.StatusOK, rr.Code, "range=%s body=%s", rng, rr.Body.String())
		rawBody := rr.Body.String()
		assert.NotContains(t, rawBody, "secret-internal.corp.example")
		assert.NotContains(t, rawBody, "hidden.internal.example")

		var payload struct {
			Locked  bool   `json:"locked"`
			Range   string `json:"range"`
			Summary struct {
				ArchiveMaxMB      float64 `json:"archive_max_mb"`
				SavedDestinations int     `json:"saved_destinations"`
				SampleCount       int64   `json:"sample_count"`
			} `json:"summary"`
			Watchlist  []any                        `json:"watchlist"`
			Jobs       []any                        `json:"jobs"`
			Timeseries []webui.CronTimeseriesBucket `json:"timeseries"`
		}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &payload))
		assert.True(t, payload.Locked)
		assert.Equal(t, rng, payload.Range)
		assert.Equal(t, float64(16), payload.Summary.ArchiveMaxMB)
		assert.Equal(t, 1, payload.Summary.SavedDestinations)
		assert.Equal(t, int64(2), payload.Summary.SampleCount)
		assert.Empty(t, payload.Watchlist)
		assert.Empty(t, payload.Jobs)
		assert.NotEmpty(t, payload.Timeseries)
	}
}

func mustCreateDest(t *testing.T, h http.Handler, body string) string {
	t.Helper()
	rr := doReq(t, h, http.MethodPost, "/api/destinations", body)
	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())
	var out struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	require.NotEmpty(t, out.Item.ID)
	return out.Item.ID
}

func assertWatchlistHasKey(t *testing.T, h http.Handler, key string, want bool) {
	t.Helper()
	rr := doReq(t, h, http.MethodGet, "/api/watchlist", "")
	require.Equal(t, http.StatusOK, rr.Code)
	var out struct {
		Items []cronmon.WatchItem `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	found := false
	for i := range out.Items {
		if out.Items[i].Key == key {
			found = true
			break
		}
	}
	assert.Equal(t, want, found, "watchlist key=%s", key)
}
