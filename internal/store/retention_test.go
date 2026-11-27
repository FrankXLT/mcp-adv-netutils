package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreOpenURIAndFilterAndSnapshotEdges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	_, err := Open(ctx, "   ", 16)
	require.Error(t, err)

	_, err = Open(ctx, "file://[::1", 16)
	require.Error(t, err)

	// Shared in-memory URI path.
	memURIStore, err := Open(ctx, "file::memory:?cache=shared", 8)
	require.NoError(t, err)
	require.NoError(t, memURIStore.Close())

	// Disk file: URI path exercises separate RO pool resolution.
	uriDBPath := filepath.Join(t.TempDir(), "uri.db")
	uriStore, err := Open(ctx, "file:"+filepath.ToSlash(uriDBPath), 8)
	require.NoError(t, err)
	defer func() { _ = uriStore.Close() }()
	assert.True(t, uriStore.separateRO)

	require.Error(t, uriStore.SaveJob(ctx, nil))
	require.Error(t, uriStore.SaveSnapshot(ctx, nil))
	require.Error(t, uriStore.SaveSnapshot(ctx, &SnapshotRecord{Name: "   "}))

	require.NoError(t, uriStore.SaveSnapshot(ctx, &SnapshotRecord{
		Name: "snap-1", JobID: "j1", Target: "1.1.1.1", PayloadJSON: `{"v":1}`,
	}))
	require.NoError(t, uriStore.SaveSnapshot(ctx, &SnapshotRecord{
		Name: "snap-1", JobID: "j2", Target: "8.8.8.8", PayloadJSON: `{"v":2}`, CreatedAt: 500,
	}))
	snap, err := uriStore.GetSnapshot(ctx, "snap-1")
	require.NoError(t, err)
	assert.Equal(t, "j2", snap.JobID)

	// ListJobs with Target, Status, Since, Until, and Offset.
	t0 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC).Unix()
	for i := range 3 {
		require.NoError(t, uriStore.SaveJob(ctx, &JobRecord{
			ToolName: "ping", Target: "10.0.0.1", Source: "cron",
			Status: "WARN", CreatedAt: t0 + int64(i*60),
		}))
	}
	list, err := uriStore.ListJobs(ctx, JobFilter{
		Target: "10.0.0.1", Status: "warn", Since: t0, Until: t0 + 120, Limit: 2, Offset: 1,
	})
	require.NoError(t, err)
	require.Len(t, list, 2)
}

func TestMergeDailyStatAndEnforceMaxStoreSizeEdges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	dst := make(map[string]CronDailyStat)
	mergeDailyStat(dst, CronDailyStat{DayUTC: "2026-11-20", JobKey: "k1", OKCount: 2, AvgDurationMS: 10, UpdatedAt: 100})
	mergeDailyStat(dst, CronDailyStat{DayUTC: "2026-11-20", JobKey: "k1", WarnCount: 2, AvgDurationMS: 30, UpdatedAt: 200})

	got := dst["2026-11-20\x00k1"]
	assert.Equal(t, int64(2), got.OKCount)
	assert.Equal(t, int64(2), got.WarnCount)
	assert.InDelta(t, 20.0, got.AvgDurationMS, 0.01)
	assert.Equal(t, int64(200), got.UpdatedAt)

	// Zero-count merge keeps AvgDurationMS safely at 0.
	mergeDailyStat(dst, CronDailyStat{DayUTC: "2026-11-21", JobKey: "k2"})
	mergeDailyStat(dst, CronDailyStat{DayUTC: "2026-11-21", JobKey: "k2"})
	assert.Equal(t, 0.0, dst["2026-11-21\x00k2"].AvgDurationMS)

	// enforceMaxStoreSize with maxStoreBytes <= 0 returns 0 immediately.
	s := openTestStore(t, 8)
	s.maxStoreBytes = 0
	evicted, err := s.enforceMaxStoreSize(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), evicted)
}
