package webui_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

type studioDeps struct {
	handler    http.Handler
	store      *store.JobStore
	scheduler  *cronmon.Scheduler
	dispatcher *dispatch.Dispatcher
	deadbolt   *security.Deadbolt
}

func newTestStudio(t *testing.T, passphrase string) studioDeps {
	t.Helper()
	return newTestStudioWithKey(t, passphrase, nil)
}

func newTestStudioWithKey(t *testing.T, passphrase string, sessionKey []byte) studioDeps {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, ":memory:", 8)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)

	var db *security.Deadbolt
	if passphrase != "" {
		db = security.NewDeadbolt(security.DeadboltConfig{
			PassHash: security.NormalizePhrase(passphrase),
			TTL:      5 * time.Minute,
		})
	}

	wl := &cronmon.WatchlistFile{
		Version: 1,
		Items: []cronmon.WatchItem{
			{Key: "gw-ping", Schedule: "*/5 * * * *", Tool: "ping", Target: "192.0.2.1", Enabled: true},
			{Key: "edge-http", Schedule: "*/5 * * * *", Tool: "http_ping", Target: "https://api.example.com", Enabled: true},
		},
	}
	sched, err := cronmon.NewScheduler(&cronmon.SchedulerConfig{
		Store:     st,
		Watchlist: wl,
		Guard:     guard,
		Runner: func(_ context.Context, item cronmon.WatchItem) (*cronmon.RunResult, error) {
			return &cronmon.RunResult{
				Status:     "OK",
				Summary:    "stub ok for " + item.Target,
				DurationMS: 12,
			}, nil
		},
	})
	require.NoError(t, err)

	disp, err := dispatch.New(dispatch.Config{
		Version:   "1.2.3-test",
		Deadbolt:  db,
		Guard:     guard,
		Store:     st,
		Scheduler: sched,
	})
	require.NoError(t, err)

	h, err := webui.NewHandler(webui.Config{
		Version:    "1.2.3-test",
		Dispatcher: disp,
		Store:      st,
		Scheduler:  sched,
		Deadbolt:   db,
		SessionKey: sessionKey,
	})
	require.NoError(t, err)

	return studioDeps{handler: h, store: st, scheduler: sched, dispatcher: disp, deadbolt: db}
}

func doReq(t *testing.T, h http.Handler, method, target, body string, headers ...[2]string) *httptest.ResponseRecorder {
	return doReqWithCookies(t, h, method, target, body, nil, headers...)
}

func doReqWithCookies(t *testing.T, h http.Handler, method, target, body string, cookies []*http.Cookie, headers ...[2]string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, target, http.NoBody)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for _, kv := range headers {
		req.Header.Set(kv[0], kv[1])
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func findCookie(t *testing.T, rr *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func decodeMap(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out), "body=%s", rr.Body.String())
	return out
}

func TestStaticAssetsAndDemoSnapshot(t *testing.T) {
	t.Parallel()
	deps := newTestStudio(t, "")

	for _, p := range []string{"/", "/index.html", "/tokens.css", "/studio.css", "/charts.js", "/studio_tool_views.js", "/studio_results.js", "/studio_destinations.js", "/studio.js", "/demo_snapshots/demo_snapshot.json"} {
		rr := doReq(t, deps.handler, http.MethodGet, p, "")
		assert.Equal(t, http.StatusOK, rr.Code, "path=%s", p)
		assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
		if p == "/" || p == "/index.html" {
			assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		}
	}

	head := doReq(t, deps.handler, http.MethodHead, "/index.html", "")
	assert.Equal(t, http.StatusOK, head.Code)
	assert.Empty(t, head.Body.String())

	for _, bad := range []string{"/../handler.go", "/demo_snapshots/../../go.mod", `/..\handler.go`} {
		rr := doReq(t, deps.handler, http.MethodGet, bad, "")
		assert.Equal(t, http.StatusNotFound, rr.Code, "bad=%s", bad)
	}

	methodErr := doReq(t, deps.handler, http.MethodPost, "/index.html", "")
	assert.Equal(t, http.StatusMethodNotAllowed, methodErr.Code)

	snap := doReq(t, deps.handler, http.MethodGet, "/api/demo_snapshot", "")
	assert.Equal(t, http.StatusOK, snap.Code)
	assert.Equal(t, "application/json; charset=utf-8", snap.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", snap.Header().Get("Cache-Control"))
	body := decodeMap(t, snap)
	assert.Contains(t, body, "summary")
	assert.Contains(t, body, "cron")
}

func TestDeadboltStatusUnlockLockAndLockout(t *testing.T) {
	t.Parallel()

	openDeps := newTestStudio(t, "")
	openStatus := doReq(t, openDeps.handler, http.MethodGet, "/api/status", "")
	assert.Equal(t, http.StatusOK, openStatus.Code)
	assert.Equal(t, map[string]any{
		"locked": false, "enabled": false, "deadbolt_enabled": false, "version": "1.2.3-test",
	}, decodeMap(t, openStatus))

	deps := newTestStudio(t, "alpha bravo charlie")

	lockedStatus := doReq(t, deps.handler, http.MethodGet, "/api/status", "")
	assert.Equal(t, http.StatusOK, lockedStatus.Code)
	stBody := decodeMap(t, lockedStatus)
	assert.Equal(t, true, stBody["locked"])
	assert.Equal(t, true, stBody["enabled"])
	assert.Equal(t, true, stBody["deadbolt_enabled"])

	// GET /api/status must stay strictly read-only and never unlock even with valid header.
	getWithValidHdr := doReq(t, deps.handler, http.MethodGet, "/api/status", "", [2]string{"X-Netutils-Passphrase", "alpha bravo charlie"})
	assert.Equal(t, http.StatusOK, getWithValidHdr.Code)
	assert.Equal(t, true, decodeMap(t, getWithValidHdr)["locked"])
	assert.Nil(t, findCookie(t, getWithValidHdr, "netutils_session"))
	assert.False(t, deps.deadbolt.IsUnlocked())

	getWithWrongHdr := doReq(t, deps.handler, http.MethodGet, "/api/status", "", [2]string{"X-Netutils-Passphrase", "wrong"})
	assert.Equal(t, http.StatusOK, getWithWrongHdr.Code)
	assert.Equal(t, true, decodeMap(t, getWithWrongHdr)["locked"])

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodPost, "/api/run"},
		{http.MethodGet, "/api/cron"},
		{http.MethodGet, "/api/jobs"},
		{http.MethodGet, "/api/jobs/job-1"},
		{http.MethodGet, "/api/watchlist"},
		{http.MethodPost, "/api/watchlist"},
	} {
		rr := doReq(t, deps.handler, tc.method, tc.path, "{}")
		assert.Equal(t, http.StatusUnauthorized, rr.Code, "%s %s", tc.method, tc.path)
		assert.Equal(t, map[string]any{"locked": true, "error": "operator studio locked"}, decodeMap(t, rr))
	}

	// Protected routes must NOT unlock via header when Deadbolt is locked.
	lockedCronWithHdr := doReq(t, deps.handler, http.MethodGet, "/api/cron", "", [2]string{"X-Netutils-Passphrase", "alpha bravo charlie"})
	assert.Equal(t, http.StatusUnauthorized, lockedCronWithHdr.Code)
	assert.False(t, deps.deadbolt.IsUnlocked())

	bigBody := `{"passphrase":"` + strings.Repeat("a", 5000) + `"}`
	tooBig := doReq(t, deps.handler, http.MethodPost, "/api/unlock", bigBody)
	assert.Equal(t, http.StatusRequestEntityTooLarge, tooBig.Code)

	badUnlock := doReq(t, deps.handler, http.MethodPost, "/api/unlock", `{"passphrase":"secret-wrong-phrase"}`)
	assert.Equal(t, http.StatusUnauthorized, badUnlock.Code)
	assert.NotContains(t, badUnlock.Body.String(), "secret-wrong-phrase")
	assert.Nil(t, findCookie(t, badUnlock, "netutils_session"))

	unlockOK := doReq(t, deps.handler, http.MethodPost, "/api/unlock", `{"passphrase":"Alpha Bravo Charlie!"}`)
	assert.Equal(t, http.StatusOK, unlockOK.Code)
	uBody := decodeMap(t, unlockOK)
	assert.Equal(t, false, uBody["locked"])
	assert.Equal(t, true, uBody["enabled"])
	assert.Equal(t, true, uBody["deadbolt_enabled"])
	assert.NotEmpty(t, uBody["expires_at"])

	sessionCookie := findCookie(t, unlockOK, "netutils_session")
	require.NotNil(t, sessionCookie)
	assert.True(t, sessionCookie.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, sessionCookie.SameSite)
	assert.Equal(t, "/", sessionCookie.Path)
	assert.Greater(t, sessionCookie.MaxAge, 0)
	assert.False(t, sessionCookie.Secure)
	assert.Contains(t, sessionCookie.Value, ".")

	// HTTPS requests set Secure on the minted cookie.
	unlockHTTPS := doReq(t, deps.handler, http.MethodPost, "/api/unlock", `{"passphrase":"Alpha Bravo Charlie!"}`, [2]string{"X-Forwarded-Proto", "https"})
	assert.Equal(t, http.StatusOK, unlockHTTPS.Code)
	httpsCookie := findCookie(t, unlockHTTPS, "netutils_session")
	require.NotNil(t, httpsCookie)
	assert.True(t, httpsCookie.Secure)

	statusWithCookie := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/status", "", []*http.Cookie{sessionCookie})
	assert.Equal(t, http.StatusOK, statusWithCookie.Code)
	assert.Equal(t, false, decodeMap(t, statusWithCookie)["locked"])

	cronWithCookie := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/cron", "", []*http.Cookie{sessionCookie})
	assert.Equal(t, http.StatusOK, cronWithCookie.Code)

	// Tampered cookie must be rejected and cleared even while Deadbolt is unlocked.
	tampered := &http.Cookie{Name: "netutils_session", Value: sessionCookie.Value + "deadbeef"}
	cronTampered := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/cron", "", []*http.Cookie{tampered})
	assert.Equal(t, http.StatusUnauthorized, cronTampered.Code)
	clearedTampered := findCookie(t, cronTampered, "netutils_session")
	require.NotNil(t, clearedTampered)
	assert.Equal(t, -1, clearedTampered.MaxAge)

	statusTampered := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/status", "", []*http.Cookie{tampered})
	assert.Equal(t, http.StatusOK, statusTampered.Code)
	assert.Equal(t, true, decodeMap(t, statusTampered)["locked"])
	clearedStatus := findCookie(t, statusTampered, "netutils_session")
	require.NotNil(t, clearedStatus)
	assert.Equal(t, -1, clearedStatus.MaxAge)

	// Without a cookie, an unlocked Deadbolt does not authorize an unauthenticated browser session.
	cronNoCookie := doReq(t, deps.handler, http.MethodGet, "/api/cron", "")
	assert.Equal(t, http.StatusUnauthorized, cronNoCookie.Code)
	statusNoCookie := doReq(t, deps.handler, http.MethodGet, "/api/status", "")
	assert.Equal(t, http.StatusOK, statusNoCookie.Code)
	assert.Equal(t, true, decodeMap(t, statusNoCookie)["locked"])
	assert.Empty(t, decodeMap(t, statusNoCookie)["expires_at"])

	lockResp := doReqWithCookies(t, deps.handler, http.MethodPost, "/api/lock", "", []*http.Cookie{sessionCookie})
	assert.Equal(t, http.StatusOK, lockResp.Code)
	assert.Equal(t, map[string]any{"locked": true, "enabled": true, "deadbolt_enabled": true}, decodeMap(t, lockResp))
	clearedLock := findCookie(t, lockResp, "netutils_session")
	require.NotNil(t, clearedLock)
	assert.Equal(t, -1, clearedLock.MaxAge)
	assert.True(t, clearedLock.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, clearedLock.SameSite)
	assert.Equal(t, "/", clearedLock.Path)

	afterLock := doReq(t, deps.handler, http.MethodGet, "/api/jobs", "")
	assert.Equal(t, http.StatusUnauthorized, afterLock.Code)

	// Replaying the prior cookie after lock fails 401 and clears the cookie.
	replayAfterLock := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/jobs", "", []*http.Cookie{sessionCookie})
	assert.Equal(t, http.StatusUnauthorized, replayAfterLock.Code)
	assert.NotNil(t, findCookie(t, replayAfterLock, "netutils_session"))

	// POST /api/unlock also accepts X-Netutils-Passphrase header fallback.
	headerUnlock := doReq(t, deps.handler, http.MethodPost, "/api/unlock", "", [2]string{"X-Netutils-Passphrase", "alpha bravo charlie"})
	assert.Equal(t, http.StatusOK, headerUnlock.Code)
	hdrCookie := findCookie(t, headerUnlock, "netutils_session")
	require.NotNil(t, hdrCookie)
	cronAfterHdrUnlock := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/cron", "", []*http.Cookie{hdrCookie})
	assert.Equal(t, http.StatusOK, cronAfterHdrUnlock.Code)

	// Trigger lockout after MaxDeadboltFailedAttempts (5).
	lockDeps := newTestStudio(t, "sierra tango")
	for i := 0; i < security.MaxDeadboltFailedAttempts-1; i++ {
		rr := doReq(t, lockDeps.handler, http.MethodPost, "/api/unlock", `{"passphrase":"bad"}`)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	}
	rateLimited := doReq(t, lockDeps.handler, http.MethodPost, "/api/unlock", `{"passphrase":"bad"}`)
	assert.Equal(t, http.StatusTooManyRequests, rateLimited.Code)
	rlBody := decodeMap(t, rateLimited)
	assert.Equal(t, true, rlBody["locked_out"])
	assert.Equal(t, "rate limited", rlBody["error"])
}

func TestSessionCookieEpochRotationRejectsPreLockReplay(t *testing.T) {
	t.Parallel()
	deps := newTestStudio(t, "alpha bravo charlie")

	unlock1 := doReq(t, deps.handler, http.MethodPost, "/api/unlock", `{"passphrase":"alpha bravo charlie"}`)
	require.Equal(t, http.StatusOK, unlock1.Code)
	preLockCookie := findCookie(t, unlock1, "netutils_session")
	require.NotNil(t, preLockCookie)
	assert.Contains(t, preLockCookie.Value, ":")
	epoch1 := deps.deadbolt.UnlockEpoch()
	require.NotZero(t, epoch1)

	require.Equal(t, http.StatusOK, doReqWithCookies(t, deps.handler, http.MethodGet, "/api/jobs", "", []*http.Cookie{preLockCookie}).Code)
	stBefore := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/status", "", []*http.Cookie{preLockCookie})
	require.Equal(t, http.StatusOK, stBefore.Code)
	assert.Equal(t, false, decodeMap(t, stBefore)["locked"])

	// Lock then immediately re-unlock within the same second; UnlockEpoch must rotate.
	require.Equal(t, http.StatusOK, doReqWithCookies(t, deps.handler, http.MethodPost, "/api/lock", "", []*http.Cookie{preLockCookie}).Code)
	unlock2 := doReq(t, deps.handler, http.MethodPost, "/api/unlock", `{"passphrase":"alpha bravo charlie"}`)
	require.Equal(t, http.StatusOK, unlock2.Code)
	postUnlockCookie := findCookie(t, unlock2, "netutils_session")
	require.NotNil(t, postUnlockCookie)
	assert.Greater(t, deps.deadbolt.UnlockEpoch(), epoch1)

	// Replaying the pre-lock cookie after re-unlock must fail 401 and report locked=true on /api/status.
	replayJobs := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/jobs", "", []*http.Cookie{preLockCookie})
	assert.Equal(t, http.StatusUnauthorized, replayJobs.Code)
	if cleared := findCookie(t, replayJobs, "netutils_session"); assert.NotNil(t, cleared) {
		assert.Equal(t, -1, cleared.MaxAge)
	}
	replayStatus := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/status", "", []*http.Cookie{preLockCookie})
	assert.Equal(t, http.StatusOK, replayStatus.Code)
	replayBody := decodeMap(t, replayStatus)
	assert.Equal(t, true, replayBody["locked"])
	assert.Empty(t, replayBody["expires_at"])
	if cleared := findCookie(t, replayStatus, "netutils_session"); assert.NotNil(t, cleared) {
		assert.Equal(t, -1, cleared.MaxAge)
	}

	// Current post-unlock cookie remains authorized while unauthenticated browser sees locked.
	assert.Equal(t, http.StatusOK, doReqWithCookies(t, deps.handler, http.MethodGet, "/api/jobs", "", []*http.Cookie{postUnlockCookie}).Code)
	stAfter := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/status", "", []*http.Cookie{postUnlockCookie})
	require.Equal(t, http.StatusOK, stAfter.Code)
	assert.Equal(t, false, decodeMap(t, stAfter)["locked"])
	assert.Equal(t, http.StatusUnauthorized, doReq(t, deps.handler, http.MethodGet, "/api/jobs", "").Code)
	stNoCookie := doReq(t, deps.handler, http.MethodGet, "/api/status", "")
	require.Equal(t, http.StatusOK, stNoCookie.Code)
	assert.Equal(t, true, decodeMap(t, stNoCookie)["locked"])
}

func signTestSessionCookie(key []byte, expiresAt time.Time, epoch uint64) *http.Cookie {
	payload := fmt.Sprintf("%d:%d", expiresAt.Unix(), epoch)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(payload))
	return &http.Cookie{
		Name:  "netutils_session",
		Value: payload + "." + hex.EncodeToString(mac.Sum(nil)),
	}
}

func parseTestSessionCookie(t *testing.T, raw string) (int64, uint64) {
	t.Helper()
	payload, _, ok := strings.Cut(raw, ".")
	require.True(t, ok)
	expStr, epochStr, ok := strings.Cut(payload, ":")
	require.True(t, ok)
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	require.NoError(t, err)
	epoch, err := strconv.ParseUint(epochStr, 10, 64)
	require.NoError(t, err)
	return expUnix, epoch
}

func TestSessionCookieSlidingRefreshFollowsDeadboltTTL(t *testing.T) {
	t.Parallel()
	for _, badKey := range [][]byte{bytes.Repeat([]byte{0x01}, 16), make([]byte, 32)} {
		_, keyErr := webui.NewHandler(webui.Config{SessionKey: badKey})
		require.Error(t, keyErr)
		assert.Contains(t, keyErr.Error(), "session key")
	}

	sessionKey := bytes.Repeat([]byte{0x42}, 32)
	deps := newTestStudioWithKey(t, "alpha bravo charlie", sessionKey)

	unlockResp := doReq(t, deps.handler, http.MethodPost, "/api/unlock", `{"passphrase":"alpha bravo charlie"}`)
	require.Equal(t, http.StatusOK, unlockResp.Code)
	initialCookie := findCookie(t, unlockResp, "netutils_session")
	require.NotNil(t, initialCookie)
	epoch1 := deps.deadbolt.UnlockEpoch()
	require.NotZero(t, epoch1)

	stBefore := deps.deadbolt.Status()
	require.True(t, stBefore.Unlocked)
	require.False(t, stBefore.ExpiresAt.IsZero())

	// Unauthenticated requests (no cookie or invalid cookie) must fail 401 without sliding Deadbolt TTL.
	time.Sleep(1100 * time.Millisecond)
	assert.Equal(t, http.StatusUnauthorized, doReq(t, deps.handler, http.MethodGet, "/api/jobs", "").Code)
	assert.Equal(t, stBefore.ExpiresAt, deps.deadbolt.Status().ExpiresAt)
	invalidCookie := &http.Cookie{Name: "netutils_session", Value: "tampered.deadbeef"}
	assert.Equal(t, http.StatusUnauthorized, doReqWithCookies(t, deps.handler, http.MethodGet, "/api/jobs", "", []*http.Cookie{invalidCookie}).Code)
	assert.Equal(t, stBefore.ExpiresAt, deps.deadbolt.Status().ExpiresAt)

	// Rapid follow-up within the +30s refresh threshold must not re-send Set-Cookie.
	freshResp := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/jobs", "", []*http.Cookie{initialCookie})
	require.Equal(t, http.StatusOK, freshResp.Code)
	assert.Nil(t, findCookie(t, freshResp, "netutils_session"))

	// A valid non-expired cookie >30s behind Deadbolt's sliding ExpiresAt must be refreshed.
	staleExp := stBefore.ExpiresAt.Add(-2 * time.Minute)
	staleCookie := signTestSessionCookie(sessionKey, staleExp, epoch1)

	refreshResp := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/jobs", "", []*http.Cookie{staleCookie})
	require.Equal(t, http.StatusOK, refreshResp.Code)
	refreshed := findCookie(t, refreshResp, "netutils_session")
	require.NotNil(t, refreshed)
	assert.True(t, refreshed.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, refreshed.SameSite)
	assert.Equal(t, "/", refreshed.Path)
	assert.Greater(t, refreshed.MaxAge, 0)
	assert.False(t, refreshed.Secure)

	stAfter := deps.deadbolt.Status()
	refreshedExp, refreshedEpoch := parseTestSessionCookie(t, refreshed.Value)
	assert.Equal(t, epoch1, refreshedEpoch)
	assert.Greater(t, refreshedExp, staleExp.Unix()+30)
	assert.GreaterOrEqual(t, refreshedExp, stBefore.ExpiresAt.Unix())
	assert.LessOrEqual(t, refreshedExp, stAfter.ExpiresAt.Unix())

	// Subsequent request using the refreshed cookie does not emit another Set-Cookie.
	followUp := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/jobs", "", []*http.Cookie{refreshed})
	require.Equal(t, http.StatusOK, followUp.Code)
	assert.Nil(t, findCookie(t, followUp, "netutils_session"))

	// HTTPS refresh sets Secure on the newly emitted cookie.
	httpsResp := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/jobs", "", []*http.Cookie{staleCookie}, [2]string{"X-Forwarded-Proto", "https"})
	require.Equal(t, http.StatusOK, httpsResp.Code)
	httpsRefreshed := findCookie(t, httpsResp, "netutils_session")
	require.NotNil(t, httpsRefreshed)
	assert.True(t, httpsRefreshed.Secure)

	// Locking invalidates and clears the refreshed cookie.
	require.Equal(t, http.StatusOK, doReqWithCookies(t, deps.handler, http.MethodPost, "/api/lock", "", []*http.Cookie{refreshed}).Code)
	lockedReplay := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/jobs", "", []*http.Cookie{refreshed})
	assert.Equal(t, http.StatusUnauthorized, lockedReplay.Code)
	if cleared := findCookie(t, lockedReplay, "netutils_session"); assert.NotNil(t, cleared) {
		assert.Equal(t, -1, cleared.MaxAge)
	}

	// Re-unlocking rotates epoch so pre-lock cookies remain rejected.
	require.Equal(t, http.StatusOK, doReq(t, deps.handler, http.MethodPost, "/api/unlock", `{"passphrase":"alpha bravo charlie"}`).Code)
	require.Greater(t, deps.deadbolt.UnlockEpoch(), epoch1)
	for _, oldCookie := range []*http.Cookie{staleCookie, refreshed} {
		rotatedReplay := doReqWithCookies(t, deps.handler, http.MethodGet, "/api/jobs", "", []*http.Cookie{oldCookie})
		assert.Equal(t, http.StatusUnauthorized, rotatedReplay.Code)
		if cleared := findCookie(t, rotatedReplay, "netutils_session"); assert.NotNil(t, cleared) {
			assert.Equal(t, -1, cleared.MaxAge)
		}
	}
}

func TestRunAndJobsEndpoints(t *testing.T) {
	t.Parallel()
	deps := newTestStudio(t, "")

	badTool := doReq(t, deps.handler, http.MethodPost, "/api/run", `{"tool":"no_such_tool"}`)
	assert.Equal(t, http.StatusBadRequest, badTool.Code)
	assert.NotEmpty(t, decodeMap(t, badTool)["error"])

	blockedTarget := doReq(t, deps.handler, http.MethodPost, "/api/run", `{"tool":"ping","target":"169.254.169.254"}`)
	assert.Equal(t, http.StatusBadRequest, blockedTarget.Code)
	assert.NotEmpty(t, decodeMap(t, blockedTarget)["error"])

	runOK := doReq(t, deps.handler, http.MethodPost, "/api/run", `{"tool":"mac_vendor_lookup","target":"00:00:5E:00:53:10","style":"quick"}`)
	require.Equal(t, http.StatusOK, runOK.Code, "body=%s", runOK.Body.String())
	runOut := decodeMap(t, runOK)
	jobID, _ := runOut["job_id"].(string)
	require.NotEmpty(t, jobID)
	assert.Equal(t, "mac_vendor_lookup", runOut["tool"])
	assert.Equal(t, "00:00:5E:00:53:10", runOut["target"])
	assert.NotEmpty(t, runOut["ascii"])

	jobByID := doReq(t, deps.handler, http.MethodGet, "/api/jobs/"+jobID+"?style=rich", "")
	require.Equal(t, http.StatusOK, jobByID.Code, "body=%s", jobByID.Body.String())
	report := decodeMap(t, jobByID)
	assert.Equal(t, jobID, report["job_id"])
	assert.Equal(t, "rich", report["style"])

	missingJob := doReq(t, deps.handler, http.MethodGet, "/api/jobs/job-does-not-exist", "")
	assert.Equal(t, http.StatusNotFound, missingJob.Code)

	badJobsLimit := doReq(t, deps.handler, http.MethodGet, "/api/jobs?limit=abc", "")
	assert.Equal(t, http.StatusBadRequest, badJobsLimit.Code)
}

func TestCronJobsFiltersAndWatchlistEndpoints(t *testing.T) {
	t.Parallel()
	deps := newTestStudio(t, "")
	ctx := context.Background()
	now := time.Now().UTC()

	// Seed cron states for 0/2 clear and 2/2 alert hysteresis plus a 1/2 warn extra state.
	_, _, err := deps.store.RecordCronTick(ctx, "gw-ping", "ping", "192.0.2.1", "OK", "job-ok", "ok", 10, now)
	require.NoError(t, err)
	_, _, err = deps.store.RecordCronTick(ctx, "edge-http", "http_ping", "https://api.example.com", "WARN", "job-w1", "slow", 120, now.Add(-2*time.Minute))
	require.NoError(t, err)
	_, _, err = deps.store.RecordCronTick(ctx, "edge-http", "http_ping", "https://api.example.com", "FAIL", "job-f2", "down", 240, now)
	require.NoError(t, err)
	_, _, err = deps.store.RecordCronTick(ctx, "dns-warn", "local_dns_query", "api.example.com", "WARN", "job-w2", "timeout", 55, now)
	require.NoError(t, err)

	// Seed jobs including an incident and a LAN radar payload containing lan_inventory.
	require.NoError(t, deps.store.SaveJob(ctx, &store.JobRecord{
		JobID: "job-inc-1", ToolName: "http_ping", Target: "https://api.example.com", Source: "cron",
		Status: "FAIL", Summary: "502 bad gateway", DurationMS: 240, CreatedAt: now.Unix(), IsIncident: true,
	}))
	lanPayload, err := json.Marshal(map[string]any{
		"lan_inventory": map[string]any{
			"physical": []map[string]any{{"ip": "192.0.2.10", "mac": "00:00:5E:00:53:10", "segment": "uaa"}},
			"virtual":  []map[string]any{{"ip": "198.51.100.11", "mac": "02:42:00:00:02:11", "segment": "laa"}},
		},
	})
	require.NoError(t, err)
	require.NoError(t, deps.store.SaveJob(ctx, &store.JobRecord{
		JobID: "job-lan-1", ToolName: "recipe_lan_radar", Target: "192.0.2.0/24", Source: "web",
		Status: "OK", Summary: "2 hosts", PayloadJSON: string(lanPayload), DurationMS: 35, CreatedAt: now.Unix(),
	}))

	badPeriod := doReq(t, deps.handler, http.MethodGet, "/api/cron?period=99d", "")
	assert.Equal(t, http.StatusBadRequest, badPeriod.Code)

	cronResp := doReq(t, deps.handler, http.MethodGet, "/api/cron?period=7d", "")
	require.Equal(t, http.StatusOK, cronResp.Code, "body=%s", cronResp.Body.String())
	var cronBody struct {
		Summary struct {
			TotalTargets   int     `json:"total_targets"`
			HealthyTargets int     `json:"healthy_targets"`
			ActiveAlerts   int     `json:"active_alerts"`
			RetainedJobs   int64   `json:"retained_jobs"`
			CronHealthPct  float64 `json:"cron_health_pct"`
		} `json:"summary"`
		Warmup    bool             `json:"warmup"`
		Strip     []map[string]any `json:"strip"`
		Watchlist []struct {
			Key            string   `json:"key"`
			Hysteresis     string   `json:"hysteresis"`
			LastTick       string   `json:"last_tick"`
			RecentStatuses []string `json:"recent_statuses"`
		} `json:"watchlist"`
		Jobs         []map[string]any           `json:"jobs"`
		LANInventory *dispatch.LANInventoryView `json:"lan_inventory"`
	}
	require.NoError(t, json.Unmarshal(cronResp.Body.Bytes(), &cronBody))
	assert.Equal(t, 3, cronBody.Summary.TotalTargets)
	assert.Equal(t, 1, cronBody.Summary.HealthyTargets)
	assert.Equal(t, 1, cronBody.Summary.ActiveAlerts)
	assert.Equal(t, int64(2), cronBody.Summary.RetainedJobs)
	assert.True(t, cronBody.Warmup)
	assert.NotEmpty(t, cronBody.Strip)
	assert.Len(t, cronBody.Jobs, 2)
	assert.NotZero(t, cronBody.Jobs[0]["duration_ms"])
	require.NotNil(t, cronBody.LANInventory)
	assert.Len(t, cronBody.LANInventory.Physical, 1)
	assert.Len(t, cronBody.LANInventory.Virtual, 1)

	hystByKey := make(map[string]string)
	recentByKey := make(map[string][]string)
	for _, w := range cronBody.Watchlist {
		hystByKey[w.Key] = w.Hysteresis
		recentByKey[w.Key] = w.RecentStatuses
		assert.NotEmpty(t, w.LastTick)
	}
	assert.Equal(t, "Healthy", hystByKey["gw-ping"])
	assert.Equal(t, "Alerting", hystByKey["edge-http"])
	assert.Equal(t, "1 failed check", hystByKey["dns-warn"])
	assert.NotContains(t, recentByKey["gw-ping"], "FAIL")
	assert.Equal(t, []string{"OK"}, recentByKey["gw-ping"])

	incJobs := doReq(t, deps.handler, http.MethodGet, "/api/jobs?incidents=1&tool=http_ping", "")
	require.Equal(t, http.StatusOK, incJobs.Code)
	incMap := decodeMap(t, incJobs)
	incList := incMap["jobs"].([]any)
	require.Len(t, incList, 1)
	assert.Equal(t, "job-inc-1", incList[0].(map[string]any)["job_id"])

	// Watchlist GET & POST delegation.
	wlList := doReq(t, deps.handler, http.MethodGet, "/api/watchlist", "")
	assert.Equal(t, http.StatusOK, wlList.Code)
	assert.Len(t, decodeMap(t, wlList)["items"].([]any), 2)

	addBody, _ := json.Marshal(map[string]any{
		"action": "add", "key": "dns-check", "schedule": "*/10 * * * *", "tool": "local_dns_query", "target": "example.com",
	})
	wlAdd := doReq(t, deps.handler, http.MethodPost, "/api/watchlist", bytes.NewBuffer(addBody).String())
	require.Equal(t, http.StatusOK, wlAdd.Code, "body=%s", wlAdd.Body.String())
	assert.Len(t, decodeMap(t, wlAdd)["items"].([]any), 3)

	wlMissing := doReq(t, deps.handler, http.MethodPost, "/api/watchlist", `{"action":"remove","key":"unknown"}`)
	assert.Equal(t, http.StatusNotFound, wlMissing.Code)
}
