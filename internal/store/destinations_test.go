package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveDestinationValidationDefaultsAndJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t, 32)

	require.Error(t, s.SaveDestination(ctx, nil))
	require.Error(t, s.SaveDestination(ctx, &SavedDestination{Name: "   ", Target: "1.1.1.1"}))
	require.Error(t, s.SaveDestination(ctx, &SavedDestination{Name: "DNS", Target: "  \t "}))

	dst := &SavedDestination{
		Name:   "  Primary Gateway  ",
		Target: "  192.168.1.1  ",
	}
	require.NoError(t, s.SaveDestination(ctx, dst))

	assert.Regexp(t, regexp.MustCompile(`^dest_[0-9a-f]{12}$`), dst.ID)
	assert.Equal(t, "Primary Gateway", dst.Name)
	assert.Equal(t, "192.168.1.1", dst.Target)
	assert.Equal(t, "Core", dst.Category)
	assert.Empty(t, dst.MAC)
	assert.Equal(t, "recipe_diff_ping", dst.DefaultCheck)
	assert.False(t, dst.Pinned)
	assert.False(t, dst.MonitorEnabled)
	assert.Equal(t, "*/5 * * * *", dst.MonitorSchedule)
	assert.Positive(t, dst.CreatedAt)
	assert.GreaterOrEqual(t, dst.UpdatedAt, dst.CreatedAt)

	raw, err := json.Marshal(dst)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	for _, key := range []string{
		"id", "name", "target", "category", "mac",
		"default_check", "pinned", "monitor_enabled", "monitor_schedule",
		"created_at", "updated_at",
	} {
		assert.Contains(t, fields, key)
	}
}

func TestSaveDestinationUpdatePreservesCreatedAt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t, 32)

	initialCreatedAt := int64(1700000100)
	dst := &SavedDestination{
		Name:            "Lab Switch",
		Target:          "10.10.0.2",
		Category:        "Switching",
		MAC:             "aa:bb:cc:dd:ee:ff",
		DefaultCheck:    "ping",
		Pinned:          true,
		MonitorEnabled:  true,
		MonitorSchedule: "*/1 * * * *",
		CreatedAt:       initialCreatedAt,
	}
	require.NoError(t, s.SaveDestination(ctx, dst))
	assert.Equal(t, initialCreatedAt, dst.CreatedAt)
	firstUpdatedAt := dst.UpdatedAt

	// Update via fresh struct with CreatedAt=0; created_at must remain initialCreatedAt.
	updateFresh := &SavedDestination{
		ID:              dst.ID,
		Name:            "Lab Core Switch",
		Target:          "10.10.0.3",
		Category:        "Infra",
		MAC:             "11:22:33:44:55:66",
		DefaultCheck:    "tcp_port_scan",
		Pinned:          false,
		MonitorEnabled:  false,
		MonitorSchedule: "*/15 * * * *",
	}
	require.NoError(t, s.SaveDestination(ctx, updateFresh))
	assert.Equal(t, initialCreatedAt, updateFresh.CreatedAt)
	assert.GreaterOrEqual(t, updateFresh.UpdatedAt, firstUpdatedAt)

	// Update with a different CreatedAt value; ON CONFLICT must still preserve original created_at.
	updateFresh2 := &SavedDestination{
		ID:        dst.ID,
		Name:      "Lab Core Switch v2",
		Target:    "10.10.0.4",
		CreatedAt: initialCreatedAt + 99999,
	}
	require.NoError(t, s.SaveDestination(ctx, updateFresh2))
	assert.Equal(t, initialCreatedAt, updateFresh2.CreatedAt)

	got, err := s.GetDestination(ctx, dst.ID)
	require.NoError(t, err)
	assert.Equal(t, initialCreatedAt, got.CreatedAt)
	assert.Equal(t, "Lab Core Switch v2", got.Name)
	assert.Equal(t, "10.10.0.4", got.Target)
	assert.Equal(t, "Core", got.Category)
	assert.Equal(t, "recipe_diff_ping", got.DefaultCheck)
	assert.Equal(t, "*/5 * * * *", got.MonitorSchedule)
}

func TestListDestinationsEmptyAndOrdering(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t, 32)

	empty, err := s.ListDestinations(ctx)
	require.NoError(t, err)
	require.NotNil(t, empty)
	assert.Empty(t, empty)

	seeds := []struct {
		name      string
		target    string
		pinned    bool
		updatedAt int64
	}{
		{name: "Alpha", target: "10.0.0.1", pinned: false, updatedAt: 1000},
		{name: "Zebra", target: "10.0.0.2", pinned: false, updatedAt: 2000},
		{name: "Bravo", target: "10.0.0.3", pinned: false, updatedAt: 2000},
		{name: "Gamma", target: "10.0.0.4", pinned: true, updatedAt: 500},
		{name: "Delta", target: "10.0.0.5", pinned: true, updatedAt: 1500},
		{name: "Charlie", target: "10.0.0.6", pinned: true, updatedAt: 1500},
	}

	for _, seed := range seeds {
		dst := &SavedDestination{
			Name:   seed.name,
			Target: seed.target,
			Pinned: seed.pinned,
		}
		require.NoError(t, s.SaveDestination(ctx, dst))
		_, err = s.rwDB.ExecContext(ctx, `UPDATE saved_destinations SET updated_at = ? WHERE id = ?;`, seed.updatedAt, dst.ID)
		require.NoError(t, err)
	}

	list, err := s.ListDestinations(ctx)
	require.NoError(t, err)
	require.Len(t, list, 6)

	gotNames := make([]string, len(list))
	for i := range list {
		gotNames[i] = list[i].Name
	}
	assert.Equal(t, []string{"Charlie", "Delta", "Gamma", "Bravo", "Zebra", "Alpha"}, gotNames)
}

func TestGetDeleteDestinationAndStoreStatsCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t, 32)

	stats0, err := s.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats0.DestinationCount)

	_, err = s.GetDestination(ctx, "dest_missing000000")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
	assert.ErrorIs(t, err, sql.ErrNoRows)

	deleted, err := s.DeleteDestination(ctx, "dest_missing000000")
	require.NoError(t, err)
	assert.False(t, deleted)

	d1 := &SavedDestination{Name: "DNS-1", Target: "1.1.1.1"}
	d2 := &SavedDestination{Name: "DNS-2", Target: "8.8.8.8", Pinned: true}
	require.NoError(t, s.SaveDestination(ctx, d1))
	require.NoError(t, s.SaveDestination(ctx, d2))

	// Updating d1 must not inflate DestinationCount.
	d1.Name = "Cloudflare"
	require.NoError(t, s.SaveDestination(ctx, d1))

	stats1, err := s.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), stats1.DestinationCount)

	deleted, err = s.DeleteDestination(ctx, d1.ID)
	require.NoError(t, err)
	assert.True(t, deleted)

	// Deleting again returns false without error.
	deletedAgain, err := s.DeleteDestination(ctx, d1.ID)
	require.NoError(t, err)
	assert.False(t, deletedAgain)

	_, err = s.GetDestination(ctx, d1.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)

	stats2, err := s.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), stats2.DestinationCount)

	got2, err := s.GetDestination(ctx, d2.ID)
	require.NoError(t, err)
	assert.Equal(t, d2.ID, got2.ID)
	assert.True(t, got2.Pinned)
}

func TestDestinationsConcurrentReadOnlyWALPool(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t, 32)
	require.True(t, s.separateRO)

	// Verify the ?mode=ro pool rejects writes to saved_destinations.
	_, writeErr := s.roDB.ExecContext(
		ctx,
		`INSERT INTO saved_destinations (id, name, target, created_at, updated_at) VALUES ('bad', 'Bad', '1.1.1.1', 1, 1);`,
	)
	require.Error(t, writeErr)

	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range 10 {
				dst := &SavedDestination{
					Name:   "Node",
					Target: "192.0.2.1",
					Pinned: (w+i)%2 == 0,
				}
				assert.NoError(t, s.SaveDestination(ctx, dst))
				got, getErr := s.GetDestination(ctx, dst.ID)
				assert.NoError(t, getErr)
				if got != nil {
					assert.Equal(t, dst.ID, got.ID)
				}
				_, listErr := s.ListDestinations(ctx)
				assert.NoError(t, listErr)
				_, statsErr := s.Stats(ctx)
				assert.NoError(t, statsErr)
			}
		}(worker)
	}
	wg.Wait()

	list, err := s.ListDestinations(ctx)
	require.NoError(t, err)
	require.Len(t, list, 40)

	stats, err := s.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(40), stats.DestinationCount)
}

func TestDestinationEdgeCasesAndRetentionBranches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t, 32)

	// Empty and whitespace-only IDs fail cleanly on GetDestination and return false on DeleteDestination.
	for _, blankID := range []string{"", "   \t "} {
		_, err := s.GetDestination(ctx, blankID)
		require.ErrorIs(t, err, ErrNotFound)
		deleted, err := s.DeleteDestination(ctx, blankID)
		require.NoError(t, err)
		assert.False(t, deleted)
	}

	// Overwrite with whitespace-padded ID preserves created_at and advances updated_at.
	dst := &SavedDestination{
		ID:        "  custom_dest_1 ",
		Name:      "Edge GW",
		Target:    "10.20.0.1",
		MAC:       "  aa:bb:cc:dd:ee:ff ",
		CreatedAt: 1700000000,
	}
	require.NoError(t, s.SaveDestination(ctx, dst))
	assert.Equal(t, "custom_dest_1", dst.ID)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", dst.MAC)

	_, err := s.rwDB.ExecContext(ctx, `UPDATE saved_destinations SET updated_at = 1700000010 WHERE id = ?;`, dst.ID)
	require.NoError(t, err)
	require.NoError(t, s.SaveDestination(ctx, &SavedDestination{
		ID:     " custom_dest_1 ",
		Name:   "Edge GW Updated",
		Target: "10.20.0.2",
	}))
	got, err := s.GetDestination(ctx, " custom_dest_1 ")
	require.NoError(t, err)
	assert.Equal(t, int64(1700000000), got.CreatedAt)
	assert.Greater(t, got.UpdatedAt, int64(1700000010))
	assert.Equal(t, "Edge GW Updated", got.Name)

	// RecordCronTick validation, empty-status -> FAIL default, duration backfill, and 7d/default period parsing.
	_, _, err = s.RecordCronTick(ctx, "   ", "ping", "1.1.1.1", "OK", "", "", 0, time.Time{})
	require.Error(t, err)

	require.NoError(t, s.SaveJob(ctx, &JobRecord{
		JobID: "backfill_j1", ToolName: "ping", Target: "1.1.1.1", Source: "cron", Status: "FAIL",
	}))
	st, flipped, err := s.RecordCronTick(ctx, "k1", "ping", "1.1.1.1", "  ", "backfill_j1", "down", 77, time.Time{})
	require.NoError(t, err)
	assert.False(t, flipped)
	assert.Equal(t, "FAIL", st.LastStatus)

	backfilled, err := s.GetJob(ctx, "backfill_j1")
	require.NoError(t, err)
	assert.Equal(t, int64(77), backfilled.DurationMS)

	sum7d, err := s.GetCronStatus(ctx, "7d")
	require.NoError(t, err)
	assert.Equal(t, "7d", sum7d.Period)
	sumDef, err := s.GetCronStatus(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, "24h", sumDef.Period)

	// Memory store RunReaperOnce(zero time) and closed store guards.
	mem, err := Open(ctx, ":memory:", 4)
	require.NoError(t, err)
	_, err = mem.DownAgeHealthyTicks(ctx, time.Time{})
	require.NoError(t, err)
	reap, err := mem.RunReaperOnce(ctx, time.Time{})
	require.NoError(t, err)
	assert.True(t, reap.VacuumRan)
	require.NoError(t, mem.Close())
	require.NoError(t, mem.Close()) // idempotent close
	mem.StartReaper(ctx, 0)         // no-op when closed

	require.Error(t, mem.SaveDestination(ctx, &SavedDestination{Name: "X", Target: "1.1.1.1"}))
	_, err = mem.GetDestination(ctx, "x")
	require.Error(t, err)
	_, err = mem.ListDestinations(ctx)
	require.Error(t, err)
	_, err = mem.DeleteDestination(ctx, "x")
	require.Error(t, err)
}
