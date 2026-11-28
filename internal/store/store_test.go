package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openTestStore(t *testing.T, maxStoreMB int) *JobStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "netutils.db")
	s, err := Open(context.Background(), dbPath, maxStoreMB)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, s.Close())
	})
	return s
}

func TestOpenWALAndReadOnlyPool(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t, 0)

	stats, err := s.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, "wal", strings.ToLower(stats.JournalMode))
	assert.Equal(t, int64(2), stats.AutoVacuum)
	assert.Equal(t, int64(DefaultMaxStoreMB)*1024*1024, stats.MaxStoreBytes)

	// Verify the separate ?mode=ro pool rejects writes while supporting concurrent reads.
	require.True(t, s.separateRO)
	_, writeErr := s.roDB.ExecContext(
		ctx,
		`INSERT INTO snapshots (name, job_id, target, payload_json, created_at) VALUES ('bad', 'j1', 't', '{}', 1);`,
	)
	require.Error(t, writeErr)

	// Verify in-memory mode also opens and functions gracefully.
	memStore, err := Open(ctx, ":memory:", 16)
	require.NoError(t, err)
	defer func() { require.NoError(t, memStore.Close()) }()
	require.NoError(t, memStore.SaveJob(ctx, &JobRecord{
		ToolName: "ping", Target: "1.1.1.1", Source: "manual", Status: "OK",
	}))
	memStats, err := memStore.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), memStats.JobCount)
}

func TestSaveGetListJobsAndDefault30dExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t, 64)

	base := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	rec := &JobRecord{
		ToolName:     "http_ping",
		Target:       "https://example.com",
		Source:       "manual",
		Status:       "OK",
		Summary:      "200 OK in 18ms",
		PayloadJSON:  `{"code":200}`,
		ASCIIDefault: "OK 200 18ms",
		DurationMS:   18,
		CreatedAt:    base.Unix(),
	}
	require.NoError(t, s.SaveJob(ctx, rec))
	assert.True(t, strings.HasPrefix(rec.JobID, "job_"))
	assert.Equal(t, base.Unix()+int64(DefaultRetention.Seconds()), rec.ExpiresAt)

	got, err := s.GetJob(ctx, rec.JobID)
	require.NoError(t, err)
	assert.Equal(t, rec, got)

	_, err = s.GetJob(ctx, "job_missing")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
	assert.ErrorIs(t, err, sql.ErrNoRows)

	incident := &JobRecord{
		ToolName:   "tls_check",
		Target:     "bad.example.com",
		Source:     "cron",
		Status:     "FAIL",
		Summary:    "cert expired",
		CreatedAt:  base.Add(time.Minute).Unix(),
		IsIncident: true,
	}
	require.NoError(t, s.SaveJob(ctx, incident))

	incidents, err := s.ListJobs(ctx, JobFilter{IncidentsOnly: true})
	require.NoError(t, err)
	require.Len(t, incidents, 1)
	assert.Equal(t, incident.JobID, incidents[0].JobID)

	filtered, err := s.ListJobs(ctx, JobFilter{ToolName: "http_ping", Source: "manual"})
	require.NoError(t, err)
	require.Len(t, filtered, 1)
	assert.Equal(t, rec.JobID, filtered[0].JobID)
}

func TestTwoTickAlertHysteresisAndCronStatus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t, 64)

	t0 := time.Now().UTC().Add(-20 * time.Minute)
	key, tool, target := "cron:ping:1.1.1.1", "ping", "1.1.1.1"

	// 1st WARN -> consecutive_non_ok=1, no active alert yet.
	st, flipped, err := s.RecordCronTick(ctx, key, tool, target, "WARN", "j1", "high jitter", 45, t0)
	require.NoError(t, err)
	assert.False(t, flipped)
	assert.False(t, st.ActiveAlert)
	assert.Equal(t, 1, st.ConsecutiveNonOK)
	assert.Equal(t, int64(0), st.LastAlertFlipAt)

	// 2nd consecutive WARN/FAIL -> consecutive_non_ok=2, alert flips ON.
	st, flipped, err = s.RecordCronTick(ctx, key, tool, target, "FAIL", "j2", "packet loss", 120, t0.Add(5*time.Minute))
	require.NoError(t, err)
	assert.True(t, flipped)
	assert.True(t, st.ActiveAlert)
	assert.Equal(t, 2, st.ConsecutiveNonOK)
	assert.Equal(t, t0.Add(5*time.Minute).Unix(), st.LastAlertFlipAt)

	// 3rd consecutive FAIL -> stays active, does NOT flip again.
	st, flipped, err = s.RecordCronTick(ctx, key, tool, target, "FAIL", "j3", "still down", 150, t0.Add(10*time.Minute))
	require.NoError(t, err)
	assert.False(t, flipped)
	assert.True(t, st.ActiveAlert)
	assert.Equal(t, 3, st.ConsecutiveNonOK)

	// 1st OK -> clears active_alert and resets consecutive_non_ok to 0.
	st, flipped, err = s.RecordCronTick(ctx, key, tool, target, "OK", "j4", "recovered", 12, t0.Add(15*time.Minute))
	require.NoError(t, err)
	assert.True(t, flipped)
	assert.False(t, st.ActiveAlert)
	assert.Equal(t, 0, st.ConsecutiveNonOK)
	assert.Equal(t, t0.Add(15*time.Minute).Unix(), st.LastAlertFlipAt)

	// Next OK -> stays clear, does not flip.
	st, flipped, err = s.RecordCronTick(ctx, key, tool, target, "OK", "j5", "healthy", 10, t0.Add(18*time.Minute))
	require.NoError(t, err)
	assert.False(t, flipped)
	assert.False(t, st.ActiveAlert)

	// Save recent cron ticks and verify GetCronStatus ("24h") executes fast and returns both states and buckets.
	require.NoError(t, s.SaveJob(ctx, &JobRecord{
		JobID: "j4", ToolName: tool, Target: target, Source: "cron",
		Status: "OK", DurationMS: 12, CreatedAt: t0.Add(15 * time.Minute).Unix(),
	}))
	start := time.Now()
	summary, err := s.GetCronStatus(ctx, "24h")
	require.NoError(t, err)
	assert.Less(t, time.Since(start), 50*time.Millisecond)
	require.Len(t, summary.States, 1)
	assert.Equal(t, key, summary.States[0].JobKey)
	require.NotEmpty(t, summary.DailyStats)

	_, err = s.GetCronStatus(ctx, "99y")
	assert.ErrorIs(t, err, ErrInvalidPeriod)
}

func TestDownAgeHealthyTicksCompactionPreservesRollups(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t, 64)

	now := time.Now().UTC().Truncate(24 * time.Hour).Add(12 * time.Hour)
	oldDay := now.Add(-10 * 24 * time.Hour)
	recentDay := now.Add(-2 * 24 * time.Hour)

	// Register cron_state key so rollups resolve to the configured job_key.
	_, _, err := s.RecordCronTick(ctx, "gw-ping", "ping", "192.168.1.1", "OK", "seed", "ok", 10, recentDay)
	require.NoError(t, err)

	// Insert 3 old OK cron ticks (should compact) and 1 old WARN incident (must stay) and 1 recent OK tick (must stay).
	for i, dur := range []int64{10, 20, 30} {
		require.NoError(t, s.SaveJob(ctx, &JobRecord{
			JobID:      "old_ok_" + string(rune('a'+i)),
			ToolName:   "ping",
			Target:     "192.168.1.1",
			Source:     "cron",
			Status:     "OK",
			DurationMS: dur,
			CreatedAt:  oldDay.Add(time.Duration(i) * time.Minute).Unix(),
		}))
	}
	require.NoError(t, s.SaveJob(ctx, &JobRecord{
		JobID:      "old_warn",
		ToolName:   "ping",
		Target:     "192.168.1.1",
		Source:     "cron",
		Status:     "WARN",
		DurationMS: 90,
		CreatedAt:  oldDay.Add(4 * time.Minute).Unix(),
		IsIncident: true,
	}))
	require.NoError(t, s.SaveJob(ctx, &JobRecord{
		JobID:      "recent_ok",
		ToolName:   "ping",
		Target:     "192.168.1.1",
		Source:     "cron",
		Status:     "OK",
		DurationMS: 15,
		CreatedAt:  recentDay.Unix(),
	}))

	compacted, err := s.DownAgeHealthyTicks(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, int64(3), compacted)

	// Add 1 more old OK tick on the same UTC day and compact again to verify weighted avg UPSERT.
	require.NoError(t, s.SaveJob(ctx, &JobRecord{
		JobID: "old_ok_d", ToolName: "ping", Target: "192.168.1.1",
		Source: "cron", Status: "OK", DurationMS: 60, CreatedAt: oldDay.Add(10 * time.Minute).Unix(),
	}))
	compacted2, err := s.DownAgeHealthyTicks(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, int64(1), compacted2)

	summary, err := s.GetCronStatus(ctx, "30d")
	require.NoError(t, err)
	var oldBucket *CronDailyStat
	for i := range summary.DailyStats {
		if summary.DailyStats[i].DayUTC == oldDay.Format("2006-01-02") {
			oldBucket = &summary.DailyStats[i]
		}
	}
	require.NotNil(t, oldBucket)
	assert.Equal(t, "gw-ping", oldBucket.JobKey)
	assert.Equal(t, int64(4), oldBucket.OKCount)
	assert.Equal(t, int64(1), oldBucket.WarnCount)
	assert.InDelta(t, 42.0, oldBucket.AvgDurationMS, 0.01) // (10+20+30+60+90)/5 = 42.0

	// Raw old OK rows should be deleted while recent_ok and old_warn remain.
	_, err = s.GetJob(ctx, "old_ok_a")
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = s.GetJob(ctx, "recent_ok")
	require.NoError(t, err)
	_, err = s.GetJob(ctx, "old_warn")
	require.NoError(t, err)
}

func TestReaperExpiryIncrementalVacuumAndMaxStoreEviction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t, 1) // 1 MiB ceiling.

	now := time.Now().UTC()
	bigPayload := strings.Repeat("A", 32*1024)

	// Seed 1 incident row that must survive size eviction + 5 expired rows + 50 live non-incident rows (~1.7 MiB).
	require.NoError(t, s.SaveJob(ctx, &JobRecord{
		JobID: "incident_keep", ToolName: "tls", Target: "core.lan", Source: "cron",
		Status: "FAIL", PayloadJSON: bigPayload, CreatedAt: now.Add(-48 * time.Hour).Unix(),
		ExpiresAt: now.Add(24 * time.Hour).Unix(), IsIncident: true,
	}))
	for i := range 5 {
		require.NoError(t, s.SaveJob(ctx, &JobRecord{
			JobID:       "expired_" + string(rune('a'+i)),
			ToolName:    "ping",
			Target:      "old.lan",
			Source:      "manual",
			Status:      "OK",
			PayloadJSON: bigPayload,
			CreatedAt:   now.Add(-40 * 24 * time.Hour).Unix(),
			ExpiresAt:   now.Add(-time.Hour).Unix(),
		}))
	}
	for i := range 50 {
		require.NoError(t, s.SaveJob(ctx, &JobRecord{
			ToolName: "http_ping", Target: "app.lan", Source: "manual", Status: "OK",
			PayloadJSON: bigPayload, CreatedAt: now.Add(-time.Duration(60-i) * time.Minute).Unix(),
			ExpiresAt: now.Add(24 * time.Hour).Unix(),
		}))
	}

	reaperStats, err := s.RunReaperOnce(ctx, now)
	require.NoError(t, err)
	assert.True(t, reaperStats.VacuumRan)
	assert.Equal(t, int64(5), reaperStats.ExpiredDeleted)
	assert.Positive(t, reaperStats.EvictedForSize)
	assert.Less(t, reaperStats.DBSizeAfter, reaperStats.DBSizeBefore)
	assert.LessOrEqual(t, reaperStats.DBSizeAfter, int64(1024*1024))

	// Incident row must never be evicted for size while within TTL.
	inc, err := s.GetJob(ctx, "incident_keep")
	require.NoError(t, err)
	assert.True(t, inc.IsIncident)
}

func TestSnapshotsAndConcurrentReadWriteAndStartReaper(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t, 32)

	require.NoError(t, s.SaveSnapshot(ctx, &SnapshotRecord{
		Name: "baseline-gw", JobID: "j100", Target: "192.168.1.1", PayloadJSON: `{"rtt_ms":1.2}`, CreatedAt: 1000,
	}))
	require.NoError(t, s.SaveSnapshot(ctx, &SnapshotRecord{
		Name: "baseline-dns", JobID: "j101", Target: "1.1.1.1", PayloadJSON: `{"rtt_ms":4.5}`, CreatedAt: 2000,
	}))
	snap, err := s.GetSnapshot(ctx, "baseline-gw")
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.1", snap.Target)

	snaps, err := s.ListSnapshots(ctx)
	require.NoError(t, err)
	require.Len(t, snaps, 2)
	assert.Equal(t, "baseline-dns", snaps[0].Name)

	_, err = s.GetSnapshot(ctx, "missing")
	assert.ErrorIs(t, err, ErrNotFound)

	// Exercise concurrent writers + ?mode=ro readers + StartReaper under -race.
	reaperCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.StartReaper(reaperCtx, 15*time.Millisecond)

	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := range 10 {
				rec := &JobRecord{
					ToolName: "ping", Target: "10.0.0.1", Source: "manual", Status: "OK",
					DurationMS: int64(worker*10 + i),
				}
				assert.NoError(t, s.SaveJob(ctx, rec))
				_, readErr := s.ListJobs(ctx, JobFilter{Limit: 10})
				assert.NoError(t, readErr)
			}
		}(g)
	}
	wg.Wait()
	time.Sleep(35 * time.Millisecond)
	cancel()
}

func TestSummarizeJobsAndFilterMetrics(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t, 32)

	empty, err := s.SummarizeJobs(ctx, JobFilter{})
	require.NoError(t, err)
	assert.Zero(t, empty.TotalMatching)
	assert.Equal(t, 0.0, empty.PassRatePct)
	assert.Empty(t, empty.TopProblemTargets)
	assert.Empty(t, empty.ToolBreakdown)

	seed := []JobRecord{
		{JobID: "j1", ToolName: "ping", Target: "edge.example.net", Source: "manual", Status: "OK", DurationMS: 10, CreatedAt: 1000},
		{JobID: "j2", ToolName: "ping", Target: "edge.example.net", Source: "cron", Status: "degraded", DurationMS: 20, CreatedAt: 2000, IsIncident: true},
		{JobID: "j3", ToolName: "http_ping", Target: "edge.example.net", Source: "cron", Status: "critical", DurationMS: 50, CreatedAt: 3000, IsIncident: true},
		{JobID: "j4", ToolName: "http_ping", Target: "core-gw.example.net", Source: "cron", Status: "FAIL", DurationMS: 40, CreatedAt: 4000, IsIncident: true},
		{JobID: "j5", ToolName: "dns_query", Target: "core-gw.example.net", Source: "manual", Status: "OK", DurationMS: 30, CreatedAt: 5000},
		{JobID: "j6", ToolName: "tls_cert", Target: "api.other.org", Source: "cron", Status: "warning", DurationMS: 60, CreatedAt: 6000, IsIncident: true},
		{JobID: "j7", ToolName: "ping", Target: "core-gw.example.net", Source: "manual", Status: "OK", DurationMS: 5, CreatedAt: 500},
	}
	for i := range seed {
		require.NoError(t, s.SaveJob(ctx, &seed[i]))
	}

	t.Run("window_aggregates_ignore_limit_and_order_breakdowns", func(t *testing.T) {
		listed, listErr := s.ListJobs(ctx, JobFilter{Since: 1000, Until: 6000, Limit: 2})
		require.NoError(t, listErr)
		require.Len(t, listed, 2)

		sum, sumErr := s.SummarizeJobs(ctx, JobFilter{Since: 1000, Until: 6000, Limit: 2})
		require.NoError(t, sumErr)
		assert.Equal(t, 6, sum.TotalMatching)
		assert.Equal(t, 2, sum.OKCount)
		assert.Equal(t, 2, sum.WarnCount)
		assert.Equal(t, 2, sum.FailCount)
		assert.Equal(t, 4, sum.IncidentCount)
		assert.InDelta(t, 33.3, sum.PassRatePct, 0.01)
		assert.InDelta(t, 35.0, sum.AvgDurationMS, 0.01)
		assert.Equal(t, int64(10), sum.MinDurationMS)
		assert.Equal(t, int64(60), sum.MaxDurationMS)
		assert.Equal(t, int64(1000), sum.EarliestCreatedAt)
		assert.Equal(t, int64(6000), sum.LatestCreatedAt)

		require.Len(t, sum.ToolBreakdown, 4)
		assert.Equal(t, ToolDigestCount{ToolName: "http_ping", Total: 2, FailCount: 2, AvgDurationMS: 45}, sum.ToolBreakdown[0])
		assert.Equal(t, ToolDigestCount{ToolName: "ping", Total: 2, OKCount: 1, WarnCount: 1, AvgDurationMS: 15}, sum.ToolBreakdown[1])
		assert.Equal(t, ToolDigestCount{ToolName: "tls_cert", Total: 1, WarnCount: 1, AvgDurationMS: 60}, sum.ToolBreakdown[2])
		assert.Equal(t, ToolDigestCount{ToolName: "dns_query", Total: 1, OKCount: 1, AvgDurationMS: 30}, sum.ToolBreakdown[3])

		require.Len(t, sum.TopProblemTargets, 3)
		assert.Equal(t, TargetProblemCount{Target: "edge.example.net", WarnCount: 1, FailCount: 1, TotalNonOK: 2, LastSeenAt: 3000}, sum.TopProblemTargets[0])
		assert.Equal(t, TargetProblemCount{Target: "core-gw.example.net", FailCount: 1, TotalNonOK: 1, LastSeenAt: 4000}, sum.TopProblemTargets[1])
		assert.Equal(t, TargetProblemCount{Target: "api.other.org", WarnCount: 1, TotalNonOK: 1, LastSeenAt: 6000}, sum.TopProblemTargets[2])
	})

	filterCases := []struct {
		name                        string
		filter                      JobFilter
		wantTotal, wantOK, wantWarn int
		wantFail                    int
		wantPassPct                 float64
	}{
		{name: "target_contains_case_insensitive", filter: JobFilter{TargetContains: "EXAMPLE.NET", Since: 1000}, wantTotal: 5, wantOK: 2, wantWarn: 1, wantFail: 2, wantPassPct: 40},
		{name: "target_contains_partial_host", filter: JobFilter{TargetContains: "core-gw"}, wantTotal: 3, wantOK: 2, wantFail: 1, wantPassPct: 66.7},
		{name: "tool_name_filter", filter: JobFilter{ToolName: "ping"}, wantTotal: 3, wantOK: 2, wantWarn: 1, wantPassPct: 66.7},
		{name: "status_fail_normalized", filter: JobFilter{Status: "fail"}, wantTotal: 2, wantFail: 2, wantPassPct: 0},
		{name: "status_warn_normalized", filter: JobFilter{Status: "warn"}, wantTotal: 2, wantWarn: 2, wantPassPct: 0},
		{name: "status_ok_normalized", filter: JobFilter{Status: "ok"}, wantTotal: 3, wantOK: 3, wantPassPct: 100},
		{name: "status_exact_fallback", filter: JobFilter{Status: "critical"}, wantTotal: 1, wantFail: 1, wantPassPct: 0},
		{name: "incidents_only_filter", filter: JobFilter{IncidentsOnly: true}, wantTotal: 4, wantWarn: 2, wantFail: 2, wantPassPct: 0},
		{name: "empty_matching_window", filter: JobFilter{Since: 9000, Until: 9999}, wantTotal: 0, wantPassPct: 0},
	}
	for _, tc := range filterCases {
		t.Run(tc.name, func(t *testing.T) {
			listed, listErr := s.ListJobs(ctx, tc.filter)
			require.NoError(t, listErr)
			assert.Len(t, listed, tc.wantTotal)

			sum, sumErr := s.SummarizeJobs(ctx, tc.filter)
			require.NoError(t, sumErr)
			assert.Equal(t, tc.wantTotal, sum.TotalMatching)
			assert.Equal(t, tc.wantOK, sum.OKCount)
			assert.Equal(t, tc.wantWarn, sum.WarnCount)
			assert.Equal(t, tc.wantFail, sum.FailCount)
			assert.InDelta(t, tc.wantPassPct, sum.PassRatePct, 0.01)
		})
	}
}
