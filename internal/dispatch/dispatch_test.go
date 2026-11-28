package dispatch

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
	"github.com/FrankXLT/mcp-adv-netutils/internal/cronmon"
	"github.com/FrankXLT/mcp-adv-netutils/internal/recipes"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/FrankXLT/mcp-adv-netutils/internal/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openTestStore(t *testing.T) *store.JobStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "dispatch-test.db")
	st, err := store.Open(context.Background(), dbPath, 32)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	return st
}

func assertASCIIWidths(t *testing.T, out *Outcome) {
	t.Helper()
	require.NotNil(t, out.ASCII)
	for _, style := range []string{ascii.StyleDefault, ascii.StyleQuick, ascii.StyleRich} {
		text := out.ASCII[style]
		require.NotEmpty(t, text, "style %s should not be empty", style)
		for _, line := range strings.Split(text, "\n") {
			w := ascii.RuneLen(line)
			switch style {
			case ascii.StyleDefault:
				assert.Equal(t, 72, w, "default line width mismatch: %q", line)
			case ascii.StyleQuick:
				assert.LessOrEqual(t, w, 40, "quick line exceeded 40 cols: %q", line)
			case ascii.StyleRich:
				assert.Equal(t, 76, w, "rich line width mismatch: %q", line)
			}
		}
	}
}

func TestToolNamesAndConfigDefaults(t *testing.T) {
	t.Parallel()

	guard, err := security.NewTargetGuard(nil, []string{"203.0.113.0/24"})
	require.NoError(t, err)
	st := openTestStore(t)

	d, err := New(Config{Version: "1.2.3", Guard: guard, Store: st})
	require.NoError(t, err)

	assert.Equal(t, "1.2.3", d.Version())
	assert.Same(t, guard, d.Guard())
	assert.Same(t, st, d.Store())
	assert.Same(t, guard, d.dnsCfg.Guard)
	assert.Same(t, guard, d.whoisCfg.Guard)
	assert.Same(t, guard, d.resCfg.Guard)
	assert.Same(t, guard, d.pingCfg.Guard)
	assert.Same(t, guard, d.httpCfg.Guard)
	assert.Same(t, guard, d.tlsCfg.Guard)

	names := d.ToolNames()
	require.Len(t, names, 33)
	expected := []string{
		"local_dns_query", "remote_dns_query", "whois_query", "resolve_hostname", "ping", "tls_certificate_check",
		"http_ping", "mac_vendor_lookup", "traceroute", "tcp_port_scan", "dns_reverse_batch", "wol_wake",
		"arp_neighbor_sweep", "mtu_path_probe", "mtr_path_quality", "mdns_ssdp_discover", "split_dns_audit",
		"snmp_switch_port", "recipe_diff_ping", "recipe_diff_dns", "recipe_diff_http", "recipe_diff_snapshot",
		"recipe_host_card", "recipe_lan_radar", "recipe_path_autopsy", "recipe_wake_verify", "render_run_digest",
		"get_cron_status", "manage_cron_watchlist", "manage_saved_destinations", "get_job_report", "unlock_netutils", "lock_netutils",
	}
	for _, tool := range expected {
		assert.Contains(t, names, tool)
	}
	names[0] = "mutated"
	assert.NotEqual(t, "mutated", d.ToolNames()[0])
}

func TestDeadboltBypassAndLockUnlock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	hash := security.NormalizePhrase("correct horse battery staple")
	db := security.NewDeadbolt(security.DeadboltConfig{PassHash: hash, TTL: 10 * time.Minute})
	d, err := New(Config{Deadbolt: db})
	require.NoError(t, err)
	assert.Same(t, db, d.Deadbolt())

	remoteCtx := transport.WithDoorway(ctx, transport.DoorwayRemote)
	lanCtx := transport.WithDoorway(ctx, transport.DoorwayLAN)
	stdioCtx := transport.WithDoorway(ctx, transport.DoorwayStdio)
	req := Request{Tool: "mac_vendor_lookup", Args: map[string]any{"target": "00:00:5E:00:53:10"}}

	_, err = d.Dispatch(remoteCtx, req)
	require.ErrorIs(t, err, ErrDeadboltLocked)

	for _, c := range []context.Context{lanCtx, stdioCtx} {
		out, dErr := d.Dispatch(c, req)
		require.NoError(t, dErr)
		assert.Equal(t, "OK", out.Status)
	}

	bypassReq := req
	bypassReq.SkipDeadbolt = true
	out, err := d.Dispatch(remoteCtx, bypassReq)
	require.NoError(t, err)
	assert.Equal(t, "OK", out.Status)

	badUnlock, err := d.Dispatch(remoteCtx, Request{Tool: "unlock_netutils", Args: map[string]any{"passphrase": "wrong phrase"}})
	require.NoError(t, err)
	assert.Equal(t, "FAIL", badUnlock.Status)
	require.NotNil(t, badUnlock.Deadbolt)
	assert.False(t, badUnlock.Deadbolt.Unlocked)

	_, err = d.Dispatch(remoteCtx, req)
	require.ErrorIs(t, err, ErrDeadboltLocked)

	okUnlock, err := d.Dispatch(remoteCtx, Request{Tool: "unlock_netutils", Args: map[string]any{"passphrase": "My spoken passphrase is: Correct, Horse-Battery Staple!"}})
	require.NoError(t, err)
	assert.Equal(t, "OK", okUnlock.Status)
	require.NotNil(t, okUnlock.Deadbolt)
	assert.True(t, okUnlock.Deadbolt.Unlocked)

	out, err = d.Dispatch(remoteCtx, req)
	require.NoError(t, err)
	assert.Equal(t, "OK", out.Status)

	lockOut, err := d.Dispatch(remoteCtx, Request{Tool: "lock_netutils"})
	require.NoError(t, err)
	assert.Equal(t, "OK", lockOut.Status)
	require.NotNil(t, lockOut.Deadbolt)
	assert.False(t, lockOut.Deadbolt.Unlocked)

	_, err = d.Dispatch(remoteCtx, req)
	require.ErrorIs(t, err, ErrDeadboltLocked)
}

func TestLockedCronSummaryRedaction(t *testing.T) {
	t.Parallel()
	ctx, st, now := context.Background(), openTestStore(t), time.Now().UTC()
	secretHost, secretIP, secretKey, secretSummary := "secret-nas.internal.home", "10.99.88.77", "secret-nas-check", "CRITICAL disk latency on secret-nas"

	require.NoError(t, st.SaveJob(ctx, &store.JobRecord{
		JobID: "job_cron_secret_1", ToolName: "ping", Target: secretHost, Source: "cron", Status: "FAIL", Summary: secretSummary,
		CreatedAt: now.Unix(), ExpiresAt: now.Add(store.DefaultRetention).Unix(), IsIncident: true,
	}))
	_, _, err := st.RecordCronTick(ctx, secretKey, "ping", secretHost, "FAIL", "job_cron_secret_1", secretSummary, 25, now)
	require.NoError(t, err)
	_, _, err = st.RecordCronTick(ctx, secretKey, "ping", secretHost, "FAIL", "job_cron_secret_1", secretSummary, 30, now.Add(time.Minute))
	require.NoError(t, err)
	_, _, err = st.RecordCronTick(ctx, "pending-gw", "ping", secretIP, "WARN", "job_cron_secret_2", "packet loss on 10.99.88.77", 12, now)
	require.NoError(t, err)

	db := security.NewDeadbolt(security.DeadboltConfig{PassHash: security.NormalizePhrase("redaction passphrase")})
	dBlocked, err := New(Config{Deadbolt: db, Store: st, AllowLockedCronSummary: false})
	require.NoError(t, err)
	remoteCtx := transport.WithDoorway(ctx, transport.DoorwayRemote)
	_, err = dBlocked.Dispatch(remoteCtx, Request{Tool: "get_cron_status", Args: map[string]any{"period": "24h"}})
	require.ErrorIs(t, err, ErrDeadboltLocked)

	dAllowed, err := New(Config{Deadbolt: db, Store: st, AllowLockedCronSummary: true})
	require.NoError(t, err)

	for _, style := range []string{ascii.StyleDefault, ascii.StyleQuick, ascii.StyleRich, ascii.StyleJSON} {
		out, dispatchErr := dAllowed.Dispatch(remoteCtx, Request{Tool: "get_cron_status", Args: map[string]any{"period": "24h"}, Style: style})
		require.NoError(t, dispatchErr)
		assert.Equal(t, "FAIL", out.Status)
		assert.Empty(t, out.Target)
		assertASCIIWidths(t, out)

		rawBytes, mErr := json.Marshal(out)
		require.NoError(t, mErr)
		wire := string(rawBytes) + "\n" + out.Output
		for _, secret := range []string{secretHost, secretIP, secretKey, secretSummary, "pending-gw"} {
			assert.NotContains(t, wire, secret)
		}
		for _, tok := range []string{"checks_total", "alerts_active", "pending_warn"} {
			assert.Contains(t, wire, tok)
		}
	}
}

func TestDispatchErrorsAndValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, err := New(Config{})
	require.NoError(t, err)

	_, err = d.Dispatch(ctx, Request{Tool: "nonexistent_tool"})
	require.ErrorIs(t, err, ErrUnknownTool)
	_, err = d.Dispatch(ctx, Request{Tool: "mac_vendor_lookup", Style: "markdown"})
	require.ErrorIs(t, err, ErrInvalidStyle)
	_, err = d.Dispatch(ctx, Request{Tool: "mac_vendor_lookup", Args: map[string]any{}})
	require.ErrorIs(t, err, ErrInvalidArgs)
	_, err = d.Dispatch(ctx, Request{Tool: "ping", Args: map[string]any{"target": "127.0.0.1", "count": "bad"}})
	require.ErrorIs(t, err, ErrInvalidArgs)
	_, err = d.GetJobReport(ctx, "job_1", "yaml")
	require.ErrorIs(t, err, ErrInvalidStyle)
	_, err = d.GetJobReport(ctx, "", "default")
	require.ErrorIs(t, err, ErrInvalidArgs)
}

func TestToolsRoundtripArchiveDigestAndAllStyles(t *testing.T) {
	t.Parallel()
	ctx, st := context.Background(), openTestStore(t)
	d, err := New(Config{Store: st})
	require.NoError(t, err)

	sched, err := cronmon.NewScheduler(&cronmon.SchedulerConfig{
		Store: st, Runner: d.CronRunner(),
		Watchlist: &cronmon.WatchlistFile{Version: 1, Items: []cronmon.WatchItem{{Key: "mac-check", Schedule: "*/5 * * * *", Tool: "mac_vendor_lookup", Target: "9C:8E:CD:0A:91:0C", Enabled: true}}},
	})
	require.NoError(t, err)
	d.SetScheduler(sched)
	assert.Same(t, sched, d.Scheduler())

	// 1. mac_vendor_lookup via Studio flat "target" alias across all 4 styles + archive persistence
	macOut, err := d.Dispatch(ctx, Request{Tool: "mac_vendor_lookup", Args: map[string]any{"target": "02:42:ac:11:00:02"}, Style: "json"})
	require.NoError(t, err)
	require.NotEmpty(t, macOut.JobID)
	assert.Equal(t, "OK", macOut.Status)
	assert.Equal(t, ascii.StyleJSON, macOut.Style)
	assert.Less(t, len(macOut.Output), ascii.MaxJSONBytes)
	assertASCIIWidths(t, macOut)
	assert.Contains(t, macOut.ASCII[ascii.StyleDefault], "LAA")

	var decodedJSON map[string]any
	require.NoError(t, json.Unmarshal([]byte(macOut.Output), &decodedJSON))
	assert.Equal(t, macOut.JobID, decodedJSON["job_id"])
	assert.Equal(t, true, decodedJSON["is_locally_administered"])

	// 2. manage_cron_watchlist add + list + run_now
	wlAdd, err := d.Dispatch(ctx, Request{Tool: "manage_cron_watchlist", Args: map[string]any{"action": "add", "key": "added-mac", "schedule": "0 * * * *", "tool": "mac_vendor_lookup", "target": "9C:8E:CD:0A:91:0C"}})
	require.NoError(t, err)
	assert.Equal(t, "OK", wlAdd.Status)
	assertASCIIWidths(t, wlAdd)

	wlRun, err := d.Dispatch(ctx, Request{Tool: "manage_cron_watchlist", Args: map[string]any{"action": "run_now", "key": "added-mac"}})
	require.NoError(t, err)
	assert.Equal(t, "OK", wlRun.Status)

	// 3. get_cron_status unlocked
	cronOut, err := d.Dispatch(ctx, Request{Tool: "get_cron_status", Args: map[string]any{"period": "7d"}, Style: "rich"})
	require.NoError(t, err)
	assert.Equal(t, "OK", cronOut.Status)
	assertASCIIWidths(t, cronOut)
	cronJSON, err := json.Marshal(cronOut.Data)
	require.NoError(t, err)
	assert.Contains(t, string(cronJSON), "added-mac")

	// 4. render_run_digest with comma-separated job_ids string
	digestOut, err := d.Dispatch(ctx, Request{Tool: "render_run_digest", Args: map[string]any{"job_ids": macOut.JobID + "," + wlAdd.JobID}, Style: "json"})
	require.NoError(t, err)
	assert.Equal(t, "OK", digestOut.Status)
	assertASCIIWidths(t, digestOut)
	assert.Contains(t, digestOut.Output, macOut.JobID)
	assert.Contains(t, digestOut.Output, wlAdd.JobID)

	// 5. get_job_report roundtrip across all 4 styles
	for _, style := range []string{ascii.StyleDefault, ascii.StyleQuick, ascii.StyleRich, ascii.StyleJSON} {
		rep, repErr := d.Dispatch(ctx, Request{Tool: "get_job_report", Args: map[string]any{"job_id": macOut.JobID}, Style: style})
		require.NoError(t, repErr)
		assert.Equal(t, macOut.JobID, rep.JobID)
		assert.Equal(t, style, rep.Style)
		assertASCIIWidths(t, rep)
		if style == ascii.StyleJSON {
			assert.Less(t, len(rep.Output), ascii.MaxJSONBytes)
		} else {
			assert.Equal(t, rep.ASCII[style], rep.Output)
		}
	}
}

func TestGetJobReportFallbackAndJSONCap(t *testing.T) {
	t.Parallel()
	ctx, st := context.Background(), openTestStore(t)
	d, err := New(Config{Store: st})
	require.NoError(t, err)

	now := time.Now().UTC()
	require.NoError(t, st.SaveJob(ctx, &store.JobRecord{
		JobID: "job_downaged_1", ToolName: "ping", Target: "192.0.2.1", Source: "cron", Status: "WARN",
		Summary: "down-aged packet loss summary", DurationMS: 42, CreatedAt: now.Unix(), ExpiresAt: now.Add(24 * time.Hour).Unix(), DownAged: true,
	}))

	for _, style := range []string{ascii.StyleDefault, ascii.StyleQuick, ascii.StyleRich, ascii.StyleJSON} {
		rep, repErr := d.GetJobReport(ctx, "job_downaged_1", style)
		require.NoError(t, repErr)
		assertASCIIWidths(t, rep)
		assert.Contains(t, rep.ASCII[ascii.StyleDefault], "down-aged packet loss summary")
		if style == ascii.StyleJSON {
			assert.Less(t, len(rep.Output), ascii.MaxJSONBytes)
		}
	}

	// Verify huge payload JSON is capped strictly under MaxJSONBytes
	bigRows := make([]ascii.TableRow, 0, 500)
	for i := range 500 {
		bigRows = append(bigRows, ascii.TableRow{Status: "OK", Cells: []string{strings.Repeat("x", 60), string(rune('A' + i%26))}})
	}
	outJSON, err := ascii.Render(&ascii.ReportCard{Title: "HUGE", ToolName: "ping", Target: "1.1.1.1", Status: "OK", Rows: bigRows}, ascii.StyleJSON)
	require.NoError(t, err)
	assert.Less(t, len(outJSON), ascii.MaxJSONBytes)
}

func TestLocalHTTPAndPortScanStudioAliasesAndCronRunner(t *testing.T) {
	t.Parallel()
	ctx, st := context.Background(), openTestStore(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	db := security.NewDeadbolt(security.DeadboltConfig{PassHash: security.NormalizePhrase("cron runner secret")})
	d, err := New(Config{Store: st, Deadbolt: db})
	require.NoError(t, err)

	// Verify CronRunner bypasses deadbolt and populates RunResult envelope
	runRes, err := d.CronRunner()(ctx, cronmon.WatchItem{Key: "cron-mac", Schedule: "*/5 * * * *", Tool: "mac_vendor_lookup", Target: "9C:8E:CD:0A:91:0C", Enabled: true})
	require.NoError(t, err)
	assert.Equal(t, "OK", runRes.Status)
	assert.NotEmpty(t, runRes.ASCIIDefault)
	assert.NotEmpty(t, runRes.PayloadJSON)

	// Verify http_ping via Studio "target" alias emits Waterfall
	lanCtx := transport.WithDoorway(ctx, transport.DoorwayLAN)
	httpOut, err := d.Dispatch(lanCtx, Request{Tool: "http_ping", Args: map[string]any{"target": srv.URL}})
	require.NoError(t, err)
	assert.Equal(t, "OK", httpOut.Status)
	assert.NotEmpty(t, httpOut.Waterfall)
	assertASCIIWidths(t, httpOut)

	// Verify tcp_port_scan explicit port and empty-ports default ("common")
	scanOut, err := d.Dispatch(lanCtx, Request{Tool: "tcp_port_scan", Args: map[string]any{"target": "127.0.0.1", "ports": portStr}})
	require.NoError(t, err)
	assert.Equal(t, "OK", scanOut.Status)
	assertASCIIWidths(t, scanOut)

	// Comma-separated record_types / compare_urls parsing
	reader := &argReader{m: map[string]any{"record_types": "A, AAAA, TXT"}}
	rts := reader.strs("record_types")
	require.NoError(t, reader.err)
	assert.Equal(t, []string{"A", "AAAA", "TXT"}, rts)
}

func TestCronStatusPeriodsAndAdminEdgeCases(t *testing.T) {
	t.Parallel()
	ctx, st, now := context.Background(), openTestStore(t), time.Now().UTC()
	for _, tk := range []struct {
		k, ip, st, id, sum string
		at                 time.Time
	}{
		{"ok-job", "127.0.0.1", "OK", "j1", "ok", now},
		{"warn-job", "127.0.0.2", "WARN", "j2", "slow", now},
		{"fail-job", "127.0.0.3", "FAIL", "j3", "down1", now},
		{"fail-job", "127.0.0.3", "FAIL", "j4", "down2", now.Add(time.Minute)},
	} {
		_, _, err := st.RecordCronTick(ctx, tk.k, "ping", tk.ip, tk.st, tk.id, tk.sum, 10, tk.at)
		require.NoError(t, err)
	}

	d, err := New(Config{Store: st, Deadbolt: security.NewDeadbolt(security.DeadboltConfig{})})
	require.NoError(t, err)
	lockDisabled, err := d.Dispatch(ctx, Request{Tool: "lock_netutils"})
	require.NoError(t, err)
	assert.Contains(t, lockDisabled.Summary, "disabled")

	sched, err := cronmon.NewScheduler(&cronmon.SchedulerConfig{Store: st, Runner: d.CronRunner()})
	require.NoError(t, err)
	for _, useSched := range []bool{false, true} {
		if useSched {
			d.SetScheduler(sched)
		}
		for _, period := range []string{"24h", "7d", "30d"} {
			out, dispatchErr := d.Dispatch(ctx, Request{Tool: "get_cron_status", Args: map[string]any{"period": period}})
			require.NoError(t, dispatchErr)
			assert.Equal(t, "FAIL", out.Status)
			assertASCIIWidths(t, out)
		}
	}

	dEmpty, err := New(Config{Deadbolt: security.NewDeadbolt(security.DeadboltConfig{PassHash: security.NormalizePhrase("secret")})})
	require.NoError(t, err)
	for _, req := range []Request{
		{Tool: "get_cron_status", Args: map[string]any{"period": "24h"}, SkipDeadbolt: true},
		{Tool: "manage_cron_watchlist", Args: map[string]any{"action": "list"}, SkipDeadbolt: true},
		{Tool: "unlock_netutils", Args: map[string]any{}},
	} {
		_, reqErr := dEmpty.Dispatch(ctx, req)
		require.Error(t, reqErr)
	}
	dEmpty.SetScheduler(sched)
	for _, args := range []map[string]any{{}, {"action": "list", "enabled": "notabool"}} {
		_, reqErr := dEmpty.Dispatch(ctx, Request{Tool: "manage_cron_watchlist", Args: args, SkipDeadbolt: true})
		require.ErrorIs(t, reqErr, ErrInvalidArgs)
	}

	assert.Nil(t, buildDailyHealthStates(nil))
	assert.Equal(t, []string{statusFAIL, statusWARN, statusOK}, buildDailyHealthStates(&store.CronSummary{
		States: []store.CronStateRecord{{ActiveAlert: true, LastStatus: statusFAIL}, {ConsecutiveNonOK: 1, LastStatus: statusWARN}, {LastStatus: statusOK}},
	}))
	assert.Equal(t, []string{statusOK, statusWARN, statusFAIL}, []string{overallAlertStatus(0, 0), overallAlertStatus(0, 1), overallAlertStatus(1, 1)})
	assert.Equal(t, []string{statusOK, statusWARN, statusFAIL}, []string{worstStatusVal(statusOK, statusOK), worstStatusVal(statusOK, statusWARN), worstStatusVal(statusWARN, statusFAIL)})
	assert.Empty(t, formatUnixTime(0))
	assert.Empty(t, formatRemainingLabel(0))
	assert.Equal(t, "expired", formatRemainingLabel(now.Add(-time.Minute).Unix()))
	assert.Contains(t, formatRemainingLabel(now.Add(5*time.Hour).Unix()), "h")
}

func TestManageSavedDestinationsLifecycleAndGuard(t *testing.T) {
	t.Parallel()
	ctx, st := context.Background(), openTestStore(t)
	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)
	db := security.NewDeadbolt(security.DeadboltConfig{PassHash: security.NormalizePhrase("dest secret")})
	d, err := New(Config{Store: st, Guard: guard, Deadbolt: db})
	require.NoError(t, err)
	sched, err := cronmon.NewScheduler(&cronmon.SchedulerConfig{Store: st, Runner: d.CronRunner(), Guard: guard})
	require.NoError(t, err)
	d.SetScheduler(sched)

	for _, badTarget := range []string{"169.254.169.254", "http://169.254.169.254/latest", "169.254.0.0/16"} {
		_, err = d.ManageSavedDestinations(ctx, DestinationParams{Action: "save", Name: "bad", Target: badTarget})
		require.ErrorIs(t, err, security.ErrTargetDenied)
	}
	_, err = d.ManageSavedDestinations(ctx, DestinationParams{Action: "save", Name: "bad", Target: "127.0.0.1", DefaultCheck: "unlock_netutils"})
	require.ErrorIs(t, err, ErrInvalidArgs)

	monOn, pinnedTrue, monOff := true, true, false
	saved, err := d.ManageSavedDestinations(ctx, DestinationParams{Action: "save", Name: "Core Switch", Target: "127.0.0.1", MAC: "  9c:8e:cd:0a:91:0c ", DefaultCheck: "mac_vendor_lookup", MonitorEnabled: &monOn})
	require.NoError(t, err)
	require.NotNil(t, saved.Item)
	id := saved.Item.ID
	assert.Equal(t, "9c:8e:cd:0a:91:0c", saved.Item.MAC)
	wl, err := sched.ManageWatchlist(ctx, cronmon.ManageParams{Action: "list"})
	require.NoError(t, err)
	require.Len(t, wl.Items, 1)
	assert.Equal(t, "dest_"+id, wl.Items[0].Key)

	upd, err := d.ManageSavedDestinations(ctx, DestinationParams{Action: "save", ID: id, Pinned: &pinnedTrue, MonitorEnabled: &monOff})
	require.NoError(t, err)
	assert.True(t, upd.Item.Pinned)
	assert.False(t, upd.Item.MonitorEnabled)
	wl, err = sched.ManageWatchlist(ctx, cronmon.ManageParams{Action: "list"})
	require.NoError(t, err)
	assert.Empty(t, wl.Items)

	remoteCtx := transport.WithDoorway(ctx, transport.DoorwayRemote)
	_, err = d.Dispatch(remoteCtx, Request{Tool: "manage_saved_destinations", Args: map[string]any{"action": "list"}})
	require.ErrorIs(t, err, ErrDeadboltLocked)

	runOut, err := d.Dispatch(remoteCtx, Request{Tool: "manage_saved_destinations", Args: map[string]any{"action": "run", "name": "Core Switch"}, SkipDeadbolt: true})
	require.NoError(t, err)
	assert.Empty(t, runOut.JobID)
	assertASCIIWidths(t, runOut)
	resData := runOut.Data.(*DestinationResult)
	require.NotNil(t, resData.Outcome)
	assert.NotEmpty(t, resData.Outcome.JobID)
	assert.Equal(t, "OK", resData.Outcome.Status)

	jobs, err := st.ListJobs(ctx, store.JobFilter{Limit: 10})
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	assert.Equal(t, "mac_vendor_lookup", jobs[0].ToolName)

	delOut, err := d.ManageSavedDestinations(ctx, DestinationParams{Action: "delete", ID: id})
	require.NoError(t, err)
	assert.Empty(t, delOut.Items)
	_, err = d.ManageSavedDestinations(ctx, DestinationParams{Action: "delete", ID: id})
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestDurationAndElapsedMSRoundTrip(t *testing.T) {
	t.Parallel()
	durZero, elapsedZero := measureDuration(time.Time{})
	assert.Equal(t, int64(0), durZero)
	assert.Zero(t, elapsedZero)

	durSub, elapsedSub := measureDuration(time.Now().Add(-150 * time.Microsecond))
	assert.Equal(t, int64(1), durSub)
	assert.GreaterOrEqual(t, elapsedSub, 0.15)

	durTiny, elapsedTiny := measureDuration(time.Now().Add(-100 * time.Nanosecond))
	assert.Equal(t, int64(1), durTiny)
	assert.GreaterOrEqual(t, elapsedTiny, 0.01)

	ctx, st := context.Background(), openTestStore(t)
	d, err := New(Config{Store: st})
	require.NoError(t, err)

	macOut, err := d.Dispatch(ctx, Request{Tool: "mac_vendor_lookup", Args: map[string]any{"target": "02:42:ac:11:00:02"}})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, macOut.DurationMS, int64(1))
	assert.Greater(t, macOut.ElapsedMS, 0.0)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	lanCtx := transport.WithDoorway(ctx, transport.DoorwayLAN)
	httpOut, err := d.Dispatch(lanCtx, Request{Tool: "http_ping", Args: map[string]any{"target": srv.URL}})
	require.NoError(t, err)
	assert.Equal(t, "OK", httpOut.Status)
	assert.GreaterOrEqual(t, httpOut.DurationMS, int64(1))
	assert.Greater(t, httpOut.ElapsedMS, 0.0)

	for _, orig := range []*Outcome{macOut, httpOut} {
		rep, repErr := d.GetJobReport(ctx, orig.JobID, ascii.StyleDefault)
		require.NoError(t, repErr)
		assert.GreaterOrEqual(t, rep.DurationMS, int64(1))
		assert.Greater(t, rep.ElapsedMS, 0.0)
		assert.InDelta(t, orig.ElapsedMS, rep.ElapsedMS, 0.0001)
	}

	fallbackOut, err := outcomeFromJobRecord(&store.JobRecord{
		JobID: "job_legacy_ms", ToolName: "ping", Target: "127.0.0.1", Status: "OK", DurationMS: 7,
	}, ascii.StyleDefault)
	require.NoError(t, err)
	assert.Equal(t, int64(7), fallbackOut.DurationMS)
	assert.Equal(t, 7.0, fallbackOut.ElapsedMS)
}

func TestDispatchRenderRunDigestWindowAndFilters(t *testing.T) {
	t.Parallel()
	ctx, st, now := context.Background(), openTestStore(t), time.Now().UTC().Unix()
	for _, r := range []*store.JobRecord{
		{JobID: "j1", ToolName: "ping", Target: "10.0.0.1", Source: "manual", Status: "OK", Summary: "ok", DurationMS: 10, CreatedAt: now - 60},
		{JobID: "j2", ToolName: "ping", Target: "10.0.0.2", Source: "cron", Status: "WARN", Summary: "jitter", DurationMS: 30, CreatedAt: now - 3600},
		{JobID: "j3", ToolName: "diff_ping", Target: "10.0.0.99", Source: "cron", Status: "FAIL", Summary: "down", DurationMS: 90, CreatedAt: now - 7200, IsIncident: true},
		{JobID: "j_old", ToolName: "ping", Target: "10.0.0.99", Source: "cron", Status: "FAIL", Summary: "old", DurationMS: 50, CreatedAt: now - 48*3600, IsIncident: true},
	} {
		require.NoError(t, st.SaveJob(ctx, r))
	}
	d, err := New(Config{Store: st})
	require.NoError(t, err)

	out, err := d.Dispatch(ctx, Request{Tool: "render_run_digest", Args: map[string]any{"window": "24h", "target": "10.0.0.", "limit": 2}, Style: ascii.StyleJSON})
	require.NoError(t, err)
	assert.Equal(t, "FAIL", out.Status)
	assertASCIIWidths(t, out)
	assert.Contains(t, out.Output, `"window_summary"`)
	data, ok := out.Data.(recipes.DigestData)
	require.True(t, ok)
	require.NotNil(t, data.WindowSummary)
	assert.Equal(t, "24h", data.Window)
	assert.Equal(t, 3, data.WindowSummary.TotalMatching)
	assert.Equal(t, 2, data.TotalJobs)

	out2, err := d.Dispatch(ctx, Request{Tool: "render_run_digest", Args: map[string]any{"window": "24h", "target": "10.0.0.99", "status": "FAIL", "incidents_only": true, "limit": 5}})
	require.NoError(t, err)
	assertASCIIWidths(t, out2)
	data2, ok := out2.Data.(recipes.DigestData)
	require.True(t, ok)
	require.NotNil(t, data2.WindowSummary)
	assert.Equal(t, 1, data2.WindowSummary.TotalMatching)
	assert.Equal(t, 1, data2.IncidentCount)
	assert.Equal(t, "j3", data2.Jobs[0].JobID)

	out3, err := d.Dispatch(ctx, Request{Tool: "render_run_digest", Args: map[string]any{"window": "24h", "target": "10.0.0.", "limit": 2}, Style: ascii.StyleJSON})
	require.NoError(t, err)
	data3, ok := out3.Data.(recipes.DigestData)
	require.True(t, ok)
	require.NotNil(t, data3.WindowSummary)
	assert.Equal(t, 3, data3.WindowSummary.TotalMatching)
	archivedDigests, err := st.ListJobs(ctx, store.JobFilter{ToolName: "render_run_digest"})
	require.NoError(t, err)
	assert.Empty(t, archivedDigests)
}
