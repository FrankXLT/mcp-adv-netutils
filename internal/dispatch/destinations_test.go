package dispatch

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/FrankXLT/mcp-adv-netutils/internal/cronmon"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateDestinationTargetNilGuardBlocksMetadata(t *testing.T) {
	t.Parallel()
	ctx, st := context.Background(), openTestStore(t)

	for _, blocked := range []string{"169.254.169.254", "http://169.254.169.254/latest/meta-data/", "169.254.0.0/16"} {
		err := validateDestinationTarget(ctx, nil, blocked)
		require.ErrorIs(t, err, security.ErrTargetDenied, "target=%s", blocked)
	}
	for _, allowed := range []string{"127.0.0.1", "192.0.2.0/24", "http://127.0.0.1:8080/healthz"} {
		require.NoError(t, validateDestinationTarget(ctx, nil, allowed), "target=%s", allowed)
	}
	for _, invalid := range []string{"http://", "not-a-cidr/99"} {
		require.Error(t, validateDestinationTarget(ctx, nil, invalid), "target=%s", invalid)
	}

	d, err := New(Config{Store: st})
	require.NoError(t, err)
	_, err = d.ManageSavedDestinations(ctx, DestinationParams{Action: "save", Name: "Meta", Target: "169.254.169.254"})
	require.ErrorIs(t, err, security.ErrTargetDenied)
}

func TestManageSavedDestinationsClearMAC(t *testing.T) {
	t.Parallel()
	ctx, st := context.Background(), openTestStore(t)
	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)
	d, err := New(Config{Store: st, Guard: guard})
	require.NoError(t, err)
	sched, err := cronmon.NewScheduler(&cronmon.SchedulerConfig{Store: st, Runner: d.CronRunner(), Guard: guard})
	require.NoError(t, err)
	d.SetScheduler(sched)

	monOn := true
	saved, err := d.ManageSavedDestinations(ctx, DestinationParams{
		Action: "save", Name: "NAS", Target: "127.0.0.1",
		MAC: "00:00:5E:00:53:10", DefaultCheck: "mac_vendor_lookup", MonitorEnabled: &monOn,
	})
	require.NoError(t, err)
	id := saved.Item.ID
	assert.Equal(t, "00:00:5E:00:53:10", saved.Item.MAC)

	// Omitting mac preserves existing MAC.
	_, err = d.Dispatch(ctx, Request{
		Tool: "manage_saved_destinations", SkipDeadbolt: true,
		Args: map[string]any{"action": "save", "id": id, "name": "NAS Renamed"},
	})
	require.NoError(t, err)
	got, err := st.GetDestination(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "00:00:5E:00:53:10", got.MAC)

	// Explicit empty "mac": "" clears MAC in SQLite and synced cron args.
	_, err = d.Dispatch(ctx, Request{
		Tool: "manage_saved_destinations", SkipDeadbolt: true,
		Args: map[string]any{"action": "save", "id": id, "mac": ""},
	})
	require.NoError(t, err)
	got, err = st.GetDestination(ctx, id)
	require.NoError(t, err)
	assert.Empty(t, got.MAC)

	wl, err := sched.ManageWatchlist(ctx, cronmon.ManageParams{Action: "list"})
	require.NoError(t, err)
	require.Len(t, wl.Items, 1)
	assert.NotContains(t, wl.Items[0].Args, "mac")

	// Direct ClearMAC flag also clears MAC.
	_, err = d.ManageSavedDestinations(ctx, DestinationParams{Action: "save", ID: id, MAC: "00:00:5E:00:53:11"})
	require.NoError(t, err)
	cleared, err := d.ManageSavedDestinations(ctx, DestinationParams{Action: "save", ID: id, ClearMAC: true})
	require.NoError(t, err)
	assert.Empty(t, cleared.Item.MAC)
}

func TestDestinationCronFirstDeleteAndSaveRollback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "dest.db")
	wlPath := filepath.Join(tmpDir, "watchlist.yaml")

	st, err := store.Open(ctx, dbPath, 16)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)
	d, err := New(Config{Store: st, Guard: guard})
	require.NoError(t, err)
	sched, err := cronmon.NewScheduler(&cronmon.SchedulerConfig{
		Store: st, WatchlistPath: wlPath, Watchlist: &cronmon.WatchlistFile{Version: 1},
		Runner: d.CronRunner(), Guard: guard,
	})
	require.NoError(t, err)
	d.SetScheduler(sched)

	monOn := true
	created, err := d.ManageSavedDestinations(ctx, DestinationParams{
		Action: "save", Name: "Core", Target: "127.0.0.1", DefaultCheck: "ping", MonitorEnabled: &monOn,
	})
	require.NoError(t, err)
	id := created.Item.ID

	// Inject SQLite BEFORE DELETE trigger so DeleteDestination fails after cron removal.
	rawDB, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	_, err = rawDB.ExecContext(ctx, `CREATE TRIGGER abort_dest_del BEFORE DELETE ON saved_destinations BEGIN SELECT RAISE(ABORT, 'forced delete failure'); END;`)
	require.NoError(t, err)
	require.NoError(t, rawDB.Close())

	_, err = d.ManageSavedDestinations(ctx, DestinationParams{Action: "delete", ID: id})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forced delete failure")

	// Rollback restored cron entry and SQLite record still exists.
	wl, err := sched.ManageWatchlist(ctx, cronmon.ManageParams{Action: "list"})
	require.NoError(t, err)
	require.Len(t, wl.Items, 1)
	assert.Equal(t, "dest_"+id, wl.Items[0].Key)
	_, err = st.GetDestination(ctx, id)
	require.NoError(t, err)

	// Drop trigger; delete now removes both cron and SQLite.
	rawDB2, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	_, err = rawDB2.ExecContext(ctx, `DROP TRIGGER abort_dest_del;`)
	require.NoError(t, err)
	require.NoError(t, rawDB2.Close())

	_, err = d.ManageSavedDestinations(ctx, DestinationParams{Action: "delete", ID: id})
	require.NoError(t, err)
	wl, err = sched.ManageWatchlist(ctx, cronmon.ManageParams{Action: "list"})
	require.NoError(t, err)
	assert.Empty(t, wl.Items)

	// Save rollback restores prior record (and deletes new failed record) when cron sync fails.
	_, err = d.ManageSavedDestinations(ctx, DestinationParams{
		Action: "save", Name: "NewBadCron", Target: "127.0.0.1", MonitorEnabled: &monOn, MonitorSchedule: "not-a-cron",
	})
	require.Error(t, err)
	listRes, err := st.ListDestinations(ctx)
	require.NoError(t, err)
	assert.Empty(t, listRes)
}

func TestReconcileDestinationMonitors(t *testing.T) {
	t.Parallel()
	ctx, st := context.Background(), openTestStore(t)
	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)

	d, err := New(Config{Store: st, Guard: guard})
	require.NoError(t, err)
	// Nil scheduler and empty store both succeed cleanly.
	require.NoError(t, d.ReconcileDestinationMonitors(ctx))

	monDst := &store.SavedDestination{
		Name: "Monitored", Target: "127.0.0.1", DefaultCheck: "ping",
		MonitorEnabled: true, MonitorSchedule: "*/15 * * * *",
	}
	unmonDst := &store.SavedDestination{
		Name: "Unmonitored", Target: "192.0.2.1", DefaultCheck: "ping", MonitorEnabled: false,
	}
	require.NoError(t, st.SaveDestination(ctx, monDst))
	require.NoError(t, st.SaveDestination(ctx, unmonDst))

	sched, err := cronmon.NewScheduler(&cronmon.SchedulerConfig{Store: st, Runner: d.CronRunner(), Guard: guard})
	require.NoError(t, err)
	d.SetScheduler(sched)

	require.NoError(t, d.ReconcileDestinationMonitors(ctx))
	wl, err := sched.ManageWatchlist(ctx, cronmon.ManageParams{Action: "list"})
	require.NoError(t, err)
	require.Len(t, wl.Items, 1)
	assert.Equal(t, "dest_"+monDst.ID, wl.Items[0].Key)
	assert.Equal(t, "*/15 * * * *", wl.Items[0].Schedule)

	// Exercise concurrent saves and monitor reconciliations under -race.
	var wg sync.WaitGroup
	for i := range 6 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			enabled := idx%2 == 0
			_, saveErr := d.ManageSavedDestinations(ctx, DestinationParams{
				Action: "save", Name: fmt.Sprintf("Host-%d", idx), Target: "127.0.0.1", MonitorEnabled: &enabled,
			})
			assert.NoError(t, saveErr)
			assert.NoError(t, d.ReconcileDestinationMonitors(ctx))
		}(i)
	}
	wg.Wait()
}
