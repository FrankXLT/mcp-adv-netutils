package webui

import (
	"context"
	"testing"
	"time"

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
