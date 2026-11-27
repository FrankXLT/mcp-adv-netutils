package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/cronmon"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTimeseriesRange(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		raw      string
		wantWin  time.Duration
		wantStep time.Duration
		wantNorm string
	}{
		{raw: "", wantWin: 24 * time.Hour, wantStep: time.Hour, wantNorm: "24h"},
		{raw: " 24H ", wantWin: 24 * time.Hour, wantStep: time.Hour, wantNorm: "24h"},
		{raw: "7d", wantWin: 7 * 24 * time.Hour, wantStep: 6 * time.Hour, wantNorm: "7d"},
		{raw: " 30D ", wantWin: 30 * 24 * time.Hour, wantStep: 24 * time.Hour, wantNorm: "30d"},
	} {
		win, step, norm, err := parseTimeseriesRange(tc.raw)
		require.NoError(t, err, tc.raw)
		assert.Equal(t, tc.wantWin, win)
		assert.Equal(t, tc.wantStep, step)
		assert.Equal(t, tc.wantNorm, norm)
	}

	_, _, _, err := parseTimeseriesRange("90d")
	require.Error(t, err)
	assert.ErrorIs(t, err, store.ErrInvalidPeriod)
}

func TestAggregateJobsToBucketsAndFinalize(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 11, 20, 12, 15, 0, 0, time.UTC)
	jobs := []store.JobRecord{
		{CreatedAt: base.Unix(), Status: "ok", DurationMS: 10},
		{CreatedAt: base.Add(10 * time.Minute).Unix(), Status: "WARN", DurationMS: 30},
		{CreatedAt: base.Add(2 * time.Hour).Unix(), Status: "FAIL", DurationMS: 50},
	}

	byTS, covered := aggregateJobsToBuckets(jobs, 3600)
	assert.True(t, covered["2026-11-20"])
	require.Len(t, byTS, 2)

	buckets, normRange, samples, err := finalizeTimeseriesBuckets(byTS, "24h")
	require.NoError(t, err)
	assert.Equal(t, "24h", normRange)
	assert.Equal(t, int64(3), samples)
	require.Len(t, buckets, 2)

	assert.Equal(t, "12:00", buckets[0].Label)
	assert.Equal(t, "WARN", buckets[0].Status)
	assert.InDelta(t, 20.0, buckets[0].AvgMS, 0.01)
	assert.InDelta(t, 10.0, buckets[0].MinMS, 0.01)
	assert.InDelta(t, 30.0, buckets[0].MaxMS, 0.01)
	assert.InDelta(t, 50.0, buckets[0].UptimePct, 0.01)

	assert.Equal(t, "14:00", buckets[1].Label)
	assert.Equal(t, "FAIL", buckets[1].Status)
	assert.InDelta(t, 0.0, buckets[1].UptimePct, 0.01)
}

func TestMergeDailyStatsIntoBucketsAndWeightedFallback(t *testing.T) {
	t.Parallel()

	byTS := make(map[int64]*tsBucketAgg)
	coveredDays := map[string]bool{"2026-11-18": true}
	daily := []store.CronDailyStat{
		{DayUTC: "2026-11-18", OKCount: 10, AvgDurationMS: 5}, // skipped: already covered
		{DayUTC: "2026-11-14", OKCount: 10, AvgDurationMS: 5}, // skipped: < sinceDay
		{DayUTC: "2026-11-21", OKCount: 10, AvgDurationMS: 5}, // skipped: > nowDay
		{DayUTC: "bad-date", OKCount: 10, AvgDurationMS: 5},   // skipped: parse error
		{DayUTC: "2026-11-16", OKCount: 0, AvgDurationMS: 5},  // skipped: zero ticks
		{DayUTC: "2026-11-17", JobKey: "a", OKCount: 2, WarnCount: 1, FailCount: 0, AvgDurationMS: 10},
		{DayUTC: "2026-11-17", JobKey: "b", OKCount: 1, WarnCount: 0, FailCount: 1, AvgDurationMS: 30},
	}

	mergeDailyStatsIntoBuckets(byTS, coveredDays, daily, "2026-11-15", "2026-11-20")
	buckets, normRange, samples, err := finalizeTimeseriesBuckets(byTS, "30d")
	require.NoError(t, err)
	assert.Equal(t, "30d", normRange)
	assert.Equal(t, int64(5), samples)
	require.Len(t, buckets, 1)

	// Weighted avg: (3*10 + 2*30) / 5 = 18.0; min=10, max=30; uptime = 3/5 * 100 = 60.0%.
	assert.Equal(t, "2026-11-17", buckets[0].Label)
	assert.Equal(t, int64(3), buckets[0].OKCount)
	assert.Equal(t, int64(1), buckets[0].WarnCount)
	assert.Equal(t, int64(1), buckets[0].FailCount)
	assert.Equal(t, "FAIL", buckets[0].Status)
	assert.InDelta(t, 18.0, buckets[0].AvgMS, 0.01)
	assert.InDelta(t, 10.0, buckets[0].MinMS, 0.01)
	assert.InDelta(t, 30.0, buckets[0].MaxMS, 0.01)
	assert.InDelta(t, 60.0, buckets[0].UptimePct, 0.01)
}

func TestBuildCronTimeseriesNilStoreEmptyAndDailyFallback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	// Nil store returns empty slice cleanly.
	buckets, norm, samples, err := buildCronTimeseries(ctx, nil, nil, "7d", now)
	require.NoError(t, err)
	assert.Equal(t, "7d", norm)
	assert.Equal(t, int64(0), samples)
	assert.Empty(t, buckets)

	// Invalid range returns store.ErrInvalidPeriod.
	_, _, _, err = buildCronTimeseries(ctx, nil, nil, "invalid", now)
	require.ErrorIs(t, err, store.ErrInvalidPeriod)

	// Store with recent job on 2026-11-20 and uncovered daily stat on 2026-11-15 in 7d mode.
	st, err := store.Open(ctx, ":memory:", 8)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	require.NoError(t, st.SaveJob(ctx, &store.JobRecord{
		JobID: "recent_1", ToolName: "ping", Target: "1.1.1.1", Source: "cron",
		Status: "OK", DurationMS: 12, CreatedAt: now.Add(-time.Hour).Unix(),
	}))
	summary := &store.CronSummary{
		DailyStats: []store.CronDailyStat{
			{DayUTC: "2026-11-15", JobKey: "ping:1.1.1.1", OKCount: 4, AvgDurationMS: 25},
			{DayUTC: "2026-11-20", JobKey: "ping:1.1.1.1", OKCount: 9, AvgDurationMS: 99},
		},
	}

	buckets, norm, samples, err = buildCronTimeseries(ctx, st, summary, "7d", now)
	require.NoError(t, err)
	assert.Equal(t, "7d", norm)
	assert.Equal(t, int64(5), samples)
	require.Len(t, buckets, 2)
	assert.Equal(t, "11-15 00:00", buckets[0].Label)
	assert.InDelta(t, 25.0, buckets[0].AvgMS, 0.01)
	assert.Equal(t, "11-20 06:00", buckets[1].Label)
	assert.InDelta(t, 12.0, buckets[1].AvgMS, 0.01)
}

func TestBuildCronTimeseries24hSameHourPerRunBuckets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 11, 20, 14, 45, 0, 0, time.UTC)

	st, err := store.Open(ctx, ":memory:", 8)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	base := time.Date(2026, 11, 20, 14, 0, 0, 0, time.UTC)
	records := []store.JobRecord{
		{
			JobID: "run_3", ToolName: "ping", Target: "1.1.1.1", Source: "cron",
			Status: "WARN", DurationMS: 45210, CreatedAt: base.Add(20*time.Minute + 30*time.Second).Unix(),
		},
		{
			JobID: "run_1", ToolName: "ping", Target: "1.1.1.1", Source: "cron",
			Status: "ok", DurationMS: 12, CreatedAt: base.Add(5*time.Minute + 10*time.Second).Unix(),
		},
		{
			JobID: "run_4", ToolName: "ping", Target: "1.1.1.1", Source: "cron",
			Status: "FAIL", DurationMS: 88, CreatedAt: base.Add(35*time.Minute + 45*time.Second).Unix(),
		},
		{
			JobID: "run_2", ToolName: "ping", Target: "1.1.1.1", Source: "cron",
			Status: "OK", DurationMS: 19, CreatedAt: base.Add(12*time.Minute + 5*time.Second).Unix(),
		},
	}
	for i := range records {
		require.NoError(t, st.SaveJob(ctx, &records[i]))
	}

	buckets, norm, samples, err := buildCronTimeseries(ctx, st, nil, "24h", now)
	require.NoError(t, err)
	assert.Equal(t, "24h", norm)
	assert.Equal(t, int64(4), samples)
	require.Len(t, buckets, 4)

	want := []struct {
		label     string
		durMS     float64
		status    string
		ok        int64
		warn      int64
		fail      int64
		uptimePct float64
	}{
		{label: "14:05:10", durMS: 12, status: "OK", ok: 1, uptimePct: 100},
		{label: "14:12:05", durMS: 19, status: "OK", ok: 1, uptimePct: 100},
		{label: "14:20:30", durMS: 45210, status: "WARN", warn: 1, uptimePct: 0},
		{label: "14:35:45", durMS: 88, status: "FAIL", fail: 1, uptimePct: 0},
	}
	for i, w := range want {
		assert.Equal(t, w.label, buckets[i].Label)
		assert.Equal(t, w.durMS, buckets[i].AvgMS)
		assert.Equal(t, w.durMS, buckets[i].MaxMS)
		assert.Equal(t, w.durMS, buckets[i].MinMS)
		assert.Equal(t, w.status, buckets[i].Status)
		assert.Equal(t, w.ok, buckets[i].OKCount)
		assert.Equal(t, w.warn, buckets[i].WarnCount)
		assert.Equal(t, w.fail, buckets[i].FailCount)
		assert.Equal(t, int64(1), buckets[i].TotalCount)
		assert.Equal(t, w.uptimePct, buckets[i].UptimePct)
	}
}

func TestCronAutoRangeSelection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, err := store.Open(ctx, ":memory:", 8)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	h, err := NewHandler(Config{Store: st})
	require.NoError(t, err)

	reqCron := func(path string) cronResponse {
		t.Helper()
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, http.StatusOK, rr.Code, "path=%s body=%s", path, rr.Body.String())
		var out cronResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
		return out
	}

	// Day 1 with 2 distinct job_keys ("gw-ping" + "wan-ping") on the same UTC day:
	// DailyStats has 2 rows, but buildStripDays spans only 1 UTC day -> warmup=true, range=24h.
	now := time.Now().UTC()
	for _, item := range []struct {
		key, target, jobID string
		durMS              int64
	}{
		{key: "gw-ping", target: "192.0.2.1", jobID: "job-day1-gw", durMS: 10},
		{key: "wan-ping", target: "198.51.100.1", jobID: "job-day1-wan", durMS: 14},
	} {
		_, _, err = st.RecordCronTick(ctx, item.key, "ping", item.target, "OK", item.jobID, "ok", item.durMS, now)
		require.NoError(t, err)
		require.NoError(t, st.SaveJob(ctx, &store.JobRecord{
			JobID: item.jobID, ToolName: "ping", Target: item.target, Source: "cron",
			Status: "OK", Summary: "ok", DurationMS: item.durMS, CreatedAt: now.Unix(),
		}))
	}

	day1 := reqCron("/api/cron?range=auto")
	assert.Equal(t, "24h", day1.Range)
	assert.True(t, day1.Warmup)
	assert.Len(t, day1.Strip, 1)

	// Day 0 adds a 2nd distinct UTC day -> warmup=false, range=30d.
	day0 := now.Add(-24 * time.Hour)
	_, _, err = st.RecordCronTick(ctx, "gw-ping", "ping", "192.0.2.1", "OK", "job-day0-gw", "ok", 12, day0)
	require.NoError(t, err)
	require.NoError(t, st.SaveJob(ctx, &store.JobRecord{
		JobID: "job-day0-gw", ToolName: "ping", Target: "192.0.2.1", Source: "cron",
		Status: "OK", Summary: "ok", DurationMS: 12, CreatedAt: day0.Unix(),
	}))

	for _, path := range []string{"/api/cron?range=auto", "/api/cron?range=AUTO"} {
		multi := reqCron(path)
		assert.Equal(t, "30d", multi.Range, "path=%s", path)
		assert.False(t, multi.Warmup, "path=%s", path)
		assert.Len(t, multi.Strip, 2, "path=%s", path)
	}

	assert.Equal(t, "24h", reqCron("/api/cron").Range)
}

func TestBuildWatchlistRowsDeduplicatesTargetAndTool(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

	items := []cronmon.WatchItem{
		{Key: "dest_pub_dns", Tool: "recipe_diff_ping", Target: "1.1.1.1"},
		{Key: "wan-public-dns-ping", Tool: "recipe_diff_ping", Target: "1.1.1.1"},
		{Key: "daily-only", Tool: "ping", Target: "192.0.2.88"},
		{Key: "unpolled-check", Tool: "ping", Target: "192.0.2.55"},
	}
	cronStatus := &store.CronSummary{
		States: []store.CronStateRecord{
			{
				JobKey: "dest_pub_dns", ToolName: "recipe_diff_ping", Target: "1.1.1.1",
				LastStatus: "WARN", ConsecutiveNonOK: 1, LastTickAt: now.Unix(),
			},
			{
				JobKey: "wan-public-dns-ping", ToolName: "recipe_diff_ping", Target: "1.1.1.1",
				LastStatus: "OK", ConsecutiveNonOK: 0, LastTickAt: now.Add(-5 * time.Minute).Unix(),
			},
			{
				JobKey: "daily-only", ToolName: "ping", Target: "192.0.2.88",
				LastStatus: "OK", ConsecutiveNonOK: 0, LastTickAt: now.Unix(),
			},
		},
		DailyStats: []store.CronDailyStat{
			{DayUTC: "2026-11-27", JobKey: "wan-public-dns-ping", OKCount: 2, AvgDurationMS: 10},
			{DayUTC: "2026-11-27", JobKey: "dest_pub_dns", OKCount: 1, WarnCount: 1, AvgDurationMS: 30},
			{DayUTC: "2026-11-26", JobKey: "daily-only", OKCount: 6, WarnCount: 2, AvgDurationMS: 15},
		},
	}
	// Jobs are ordered newest-first as returned by store.JobStore.ListJobs.
	// Includes >8 matching runs (to verify cap=8, oldest->newest) and an unrelated FAIL.
	jobs := []store.JobRecord{
		{JobID: "unrelated-fail", ToolName: "http_ping", Target: "https://other.example", Status: "FAIL", DurationMS: 999},
		{JobID: "j10", ToolName: "recipe_diff_ping", Target: "1.1.1.1", Status: "WARN", DurationMS: 44},
		{JobID: "j9", ToolName: "recipe_diff_ping", Target: "1.1.1.1", Status: "OK", DurationMS: 12},
		{JobID: "j8", ToolName: "recipe_diff_ping", Target: "1.1.1.1", Status: "OK", DurationMS: 14},
		{JobID: "j7", ToolName: "recipe_diff_ping", Target: "1.1.1.1", Status: "FAIL", DurationMS: 55},
		{JobID: "j6", ToolName: "recipe_diff_ping", Target: "1.1.1.1", Status: "OK", DurationMS: 11},
		{JobID: "j5", ToolName: "recipe_diff_ping", Target: "1.1.1.1", Status: "OK", DurationMS: 13},
		{JobID: "j4", ToolName: "recipe_diff_ping", Target: "1.1.1.1", Status: "OK", DurationMS: 15},
		{JobID: "j3", ToolName: "recipe_diff_ping", Target: "1.1.1.1", Status: "OK", DurationMS: 10},
		{JobID: "j2", ToolName: "recipe_diff_ping", Target: "1.1.1.1", Status: "FAIL", DurationMS: 12}, // dropped (>8)
	}

	rows := buildWatchlistRows(items, cronStatus, jobs)
	require.Len(t, rows, 3)

	merged := rows[0]
	assert.Equal(t, "wan-public-dns-ping", merged.Key)
	assert.Equal(t, "recipe_diff_ping", merged.Check)
	assert.Equal(t, "1.1.1.1", merged.Target)
	assert.Equal(t, "WARN", merged.Health)
	assert.Equal(t, "1 failed check", merged.Hysteresis)
	assert.Equal(t, now.Format(time.RFC3339), merged.LastTick)
	// Weighted avg across both keys: (2*10 + 2*30) / 4 = 20.0; max from matching jobs = 55.0.
	assert.InDelta(t, 20.0, merged.AvgMS, 0.01)
	assert.InDelta(t, 55.0, merged.MaxMS, 0.01)
	assert.Equal(t, []string{"OK", "OK", "OK", "OK", "FAIL", "OK", "OK", "WARN"}, merged.RecentStatuses)

	dailyOnly := rows[1]
	assert.Equal(t, "daily-only", dailyOnly.Key)
	assert.Equal(t, []string{"WARN", "WARN", "OK", "OK", "OK", "OK", "OK", "OK"}, dailyOnly.RecentStatuses)

	unpolled := rows[2]
	assert.Equal(t, "unpolled-check", unpolled.Key)
	assert.Nil(t, unpolled.RecentStatuses)
}

func TestBuildWatchlistRowsSkipsStaleDestStateAndUsesNewestTick(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 27, 15, 0, 0, 0, time.UTC)

	items := []cronmon.WatchItem{
		{Key: "wan-public-dns-ping", Tool: "recipe_diff_ping", Target: "1.1.1.1"},
		{Key: "dest_active_dns", Tool: "recipe_diff_ping", Target: "1.1.1.1"},
	}
	cronStatus := &store.CronSummary{
		States: []store.CronStateRecord{
			{
				JobKey: "dest_removed_orphan", ToolName: "http_ping", Target: "https://removed.example",
				LastStatus: "FAIL", ActiveAlert: true, ConsecutiveNonOK: 2, LastTickAt: now.Unix(),
			},
			{
				JobKey: "dest_disabled_old", ToolName: "recipe_diff_ping", Target: "1.1.1.1",
				LastStatus: "FAIL", ActiveAlert: true, ConsecutiveNonOK: 3, LastTickAt: now.Add(-15 * time.Minute).Unix(),
			},
			{
				JobKey: "dest_active_dns", ToolName: "recipe_diff_ping", Target: "1.1.1.1",
				LastStatus: "FAIL", ActiveAlert: true, ConsecutiveNonOK: 2, LastTickAt: now.Add(-5 * time.Minute).Unix(),
			},
			{
				JobKey: "wan-public-dns-ping", ToolName: "recipe_diff_ping", Target: "1.1.1.1",
				LastStatus: "OK", ActiveAlert: false, ConsecutiveNonOK: 0, LastTickAt: now.Unix(),
			},
		},
	}

	rows := buildWatchlistRows(items, cronStatus, nil)
	require.Len(t, rows, 1)
	assert.Equal(t, "wan-public-dns-ping", rows[0].Key)
	assert.Equal(t, "OK", rows[0].Health)
	assert.Equal(t, "Healthy", rows[0].Hysteresis)
	assert.Equal(t, now.Format(time.RFC3339), rows[0].LastTick)
}
