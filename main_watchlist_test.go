package main

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/FrankXLT/mcp-adv-netutils/internal/cronmon"
	"github.com/FrankXLT/mcp-adv-netutils/internal/dispatch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatchlistExplicitAndSeedingFromReadOnlySource(t *testing.T) {
	t.Parallel()

	cfgDefault, err := parseConfig([]string{"--data-dir", t.TempDir()}, mapEnv(nil), io.Discard)
	require.NoError(t, err)
	assert.False(t, cfgDefault.WatchlistExplicit)

	cfgFlag, err := parseConfig([]string{"--data-dir", t.TempDir(), "--watchlist", "/tmp/w.yaml"}, mapEnv(nil), io.Discard)
	require.NoError(t, err)
	assert.True(t, cfgFlag.WatchlistExplicit)

	cfgEnv, err := parseConfig([]string{"--data-dir", t.TempDir()}, mapEnv(map[string]string{"NETUTILS_WATCHLIST": "/tmp/env.yaml"}), io.Discard)
	require.NoError(t, err)
	assert.True(t, cfgEnv.WatchlistExplicit)

	roDir := filepath.Join(t.TempDir(), "app")
	require.NoError(t, os.MkdirAll(roDir, 0o750))
	roFile := filepath.Join(roDir, defaultWatchlistFile)
	roContent := "version: 1\nitems:\n  - key: ro-seeded\n    schedule: \"*/5 * * * *\"\n    tool: ping\n    target: 127.0.0.1\n    enabled: true\n"
	require.NoError(t, os.WriteFile(roFile, []byte(roContent), 0o444))
	require.NoError(t, os.Chmod(roDir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o750) })

	dataDir := t.TempDir()
	seededPath := seedWritableWatchlist(dataDir, roFile)
	wantPath := filepath.Join(dataDir, defaultWatchlistFile)
	assert.Equal(t, wantPath, seededPath)

	raw, err := os.ReadFile(seededPath)
	require.NoError(t, err)
	assert.Equal(t, roContent, string(raw))
	info, err := os.Stat(seededPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	customContent := "version: 1\nitems:\n  - key: custom-keep\n    schedule: \"*/10 * * * *\"\n    tool: ping\n    target: 127.0.0.1\n    enabled: true\n"
	require.NoError(t, os.WriteFile(seededPath, []byte(customContent), 0o600))
	assert.Equal(t, wantPath, seedWritableWatchlist(dataDir, roFile))

	preserved, err := os.ReadFile(seededPath)
	require.NoError(t, err)
	assert.Equal(t, customContent, string(preserved))

	emptyDataDir := t.TempDir()
	emptySeeded := seedWritableWatchlist(emptyDataDir, "")
	assert.Equal(t, filepath.Join(emptyDataDir, defaultWatchlistFile), emptySeeded)
	emptyRaw, err := os.ReadFile(emptySeeded)
	require.NoError(t, err)
	assert.Equal(t, defaultWatchlistYAML, string(emptyRaw))
}

func TestInitRuntimeSeedsWritableWatchlistAndReconcilesMonitors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	roDir := filepath.Join(t.TempDir(), "app")
	require.NoError(t, os.MkdirAll(roDir, 0o750))
	roFile := filepath.Join(roDir, defaultWatchlistFile)
	require.NoError(t, os.WriteFile(roFile, []byte("version: 1\nitems: []\n"), 0o444))
	require.NoError(t, os.Chmod(roDir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o750) })

	dataDir := t.TempDir()
	cfg1, err := parseConfig([]string{"--http", "--data-dir", dataDir}, mapEnv(nil), io.Discard)
	require.NoError(t, err)
	cfg1.WatchlistPath = roFile
	cfg1.WatchlistExplicit = false

	rt1, err := initRuntime(ctx, cfg1, log.New(io.Discard, "", 0))
	require.NoError(t, err)

	_, err = rt1.scheduler.ManageWatchlist(ctx, cronmon.ManageParams{
		Action: "add", Key: "seeded-writable-check", Schedule: "*/5 * * * *",
		Tool: "mac_vendor_lookup", Target: "02:42:ac:11:00:02",
	})
	require.NoError(t, err)

	monOn, monOff := true, false
	monSaved, err := rt1.dispatcher.ManageSavedDestinations(ctx, dispatch.DestinationParams{
		Action: "save", Name: "Monitored GW", Target: "127.0.0.1",
		DefaultCheck: "ping", MonitorEnabled: &monOn, MonitorSchedule: "*/10 * * * *",
	})
	require.NoError(t, err)
	require.NotNil(t, monSaved.Item)

	unmonSaved, err := rt1.dispatcher.ManageSavedDestinations(ctx, dispatch.DestinationParams{
		Action: "save", Name: "Unmonitored Host", Target: "192.0.2.50",
		DefaultCheck: "ping", MonitorEnabled: &monOff,
	})
	require.NoError(t, err)
	require.NotNil(t, unmonSaved.Item)
	require.NoError(t, rt1.jobStore.Close())

	// Simulate restart with fresh seeded /data/watchlist.yaml lacking dest_<id>.
	writableWL := filepath.Join(dataDir, defaultWatchlistFile)
	require.NoError(t, os.Remove(writableWL))

	cfg2, err := parseConfig([]string{"--http", "--data-dir", dataDir}, mapEnv(nil), io.Discard)
	require.NoError(t, err)
	cfg2.WatchlistPath = roFile
	cfg2.WatchlistExplicit = false

	rt2, err := initRuntime(ctx, cfg2, log.New(io.Discard, "", 0))
	require.NoError(t, err)
	defer func() { _ = rt2.jobStore.Close() }()

	wlRes, err := rt2.scheduler.ManageWatchlist(ctx, cronmon.ManageParams{Action: "list"})
	require.NoError(t, err)
	keys := make(map[string]cronmon.WatchItem, len(wlRes.Items))
	for i := range wlRes.Items {
		keys[wlRes.Items[i].Key] = wlRes.Items[i]
	}

	monKey := "dest_" + monSaved.Item.ID
	require.Contains(t, keys, monKey)
	assert.Equal(t, "*/10 * * * *", keys[monKey].Schedule)
	assert.Equal(t, "ping", keys[monKey].Tool)
	assert.Equal(t, "127.0.0.1", keys[monKey].Target)
	assert.True(t, keys[monKey].Enabled)
	assert.NotContains(t, keys, "dest_"+unmonSaved.Item.ID)

	wlBytes, err := os.ReadFile(writableWL)
	require.NoError(t, err)
	assert.Contains(t, string(wlBytes), monKey)
}
