package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeadboltUnlockEpochRotation(t *testing.T) {
	var nilDB *Deadbolt
	assert.Equal(t, uint64(0), nilDB.UnlockEpoch())

	disabled := NewDeadbolt(DeadboltConfig{})
	assert.Equal(t, uint64(0), disabled.UnlockEpoch())
	ok, _, reason := disabled.Unlock("anything")
	require.True(t, ok)
	assert.Equal(t, "deadbolt disabled", reason)
	assert.Equal(t, uint64(0), disabled.UnlockEpoch())
	disabled.Lock()
	assert.Equal(t, uint64(0), disabled.UnlockEpoch())

	var tick atomic.Int64
	base := time.Date(2026, 2, 1, 9, 0, 0, 0, time.UTC)
	tick.Store(base.UnixNano())

	d := NewDeadbolt(DeadboltConfig{
		PassHash: NormalizePhrase("correct horse battery staple"),
		TTL:      MinDeadboltTTL,
	})
	d.now = func() time.Time {
		return time.Unix(0, tick.Load()).UTC()
	}

	assert.Equal(t, uint64(0), d.UnlockEpoch())

	// Locking before any unlock keeps epoch unchanged at 0.
	d.Lock()
	assert.Equal(t, uint64(0), d.UnlockEpoch())

	// Failed unlock attempts do not rotate epoch.
	ok, _, _ = d.Unlock("wrong passphrase")
	assert.False(t, ok)
	assert.Equal(t, uint64(0), d.UnlockEpoch())

	// First Unlock() yields a non-zero epoch.
	ok, _, _ = d.Unlock("correct horse battery staple")
	require.True(t, ok)
	epoch1 := d.UnlockEpoch()
	assert.Greater(t, epoch1, uint64(0))

	// Re-Unlock() while already unlocked slides TTL without rotating epoch.
	tick.Store(base.Add(10 * time.Second).UnixNano())
	ok, expiresAt, _ := d.Unlock("my spoken passphrase is correct horse battery staple")
	require.True(t, ok)
	assert.Equal(t, base.Add(10*time.Second).Add(MinDeadboltTTL), expiresAt)
	assert.Equal(t, epoch1, d.UnlockEpoch())

	// Lock() within the exact same clock tick rotates epoch.
	d.Lock()
	assert.False(t, d.IsUnlocked())
	epoch2 := d.UnlockEpoch()
	assert.Greater(t, epoch2, epoch1)

	// Idempotent Lock() while already locked keeps epoch2.
	d.Lock()
	assert.Equal(t, epoch2, d.UnlockEpoch())

	// Subsequent Unlock() within the exact same clock tick yields a fresh epoch.
	ok, _, _ = d.Unlock("correct horse battery staple")
	require.True(t, ok)
	epoch3 := d.UnlockEpoch()
	assert.Greater(t, epoch3, epoch2)
	assert.NotEqual(t, epoch1, epoch3)

	// TTL expiration observed via IsUnlocked() rotates epoch, and re-Unlock() rotates again.
	tick.Store(base.Add(10*time.Second + MinDeadboltTTL).UnixNano())
	assert.False(t, d.IsUnlocked())
	epoch4 := d.UnlockEpoch()
	assert.Greater(t, epoch4, epoch3)

	ok, _, _ = d.Unlock("correct horse battery staple")
	require.True(t, ok)
	epoch5 := d.UnlockEpoch()
	assert.Greater(t, epoch5, epoch4)

	// TTL expiration without an intervening IsUnlocked() still rotates epoch on Unlock().
	tick.Store(base.Add(10*time.Second + 2*MinDeadboltTTL).UnixNano())
	ok, _, _ = d.Unlock("correct horse battery staple")
	require.True(t, ok)
	epoch6 := d.UnlockEpoch()
	assert.Greater(t, epoch6, epoch5)
}

func TestDeadboltUnlockEpochPersistenceAndConcurrency(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "deadbolt_epoch.json")
	hash := NormalizePhrase("hotel foxtrot")
	now := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)

	d1 := NewDeadbolt(DeadboltConfig{PassHash: hash, StatePath: statePath})
	d1.now = func() time.Time { return now }

	ok, _, _ := d1.Unlock("hotel foxtrot")
	require.True(t, ok)
	e1 := d1.UnlockEpoch()
	require.Equal(t, uint64(1), e1)

	raw, err := os.ReadFile(statePath)
	require.NoError(t, err)
	var persisted map[string]any
	require.NoError(t, json.Unmarshal(raw, &persisted))
	assert.Equal(t, float64(1), persisted["unlock_epoch"])

	// Reload while unlocked preserves epoch; Lock() and Unlock() continue monotonically.
	d2 := NewDeadbolt(DeadboltConfig{PassHash: hash, StatePath: statePath})
	d2.now = func() time.Time { return now }
	assert.True(t, d2.IsUnlocked())
	assert.Equal(t, e1, d2.UnlockEpoch())

	d2.Lock()
	e2 := d2.UnlockEpoch()
	assert.Greater(t, e2, e1)

	// Reload while locked preserves post-Lock epoch so pre-lock cookies never replay after restart.
	d3 := NewDeadbolt(DeadboltConfig{PassHash: hash, StatePath: statePath})
	d3.now = func() time.Time { return now }
	assert.False(t, d3.IsUnlocked())
	assert.Equal(t, e2, d3.UnlockEpoch())

	ok, _, _ = d3.Unlock("hotel foxtrot")
	require.True(t, ok)
	e3 := d3.UnlockEpoch()
	assert.Greater(t, e3, e2)

	// Legacy persisted state without unlock_epoch promotes unlocked sessions to non-zero epoch.
	legacyPath := filepath.Join(t.TempDir(), "legacy_deadbolt.json")
	legacyData, err := json.Marshal(deadboltPersistedState{
		PassHashDigest: d1.passHashFingerprint(),
		UnlockedAt:     now,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(legacyPath, legacyData, 0o600))

	dLegacy := NewDeadbolt(DeadboltConfig{PassHash: hash, StatePath: legacyPath})
	dLegacy.now = func() time.Time { return now }
	assert.True(t, dLegacy.IsUnlocked())
	assert.NotZero(t, dLegacy.UnlockEpoch())

	// Concurrent Unlock / Lock / UnlockEpoch stress under -race.
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for step := range 20 {
				if (id+step)%3 == 0 {
					_, _, _ = d3.Unlock("hotel foxtrot")
				} else if (id+step)%3 == 1 {
					d3.Lock()
				}
				_ = d3.UnlockEpoch()
				_ = d3.IsUnlocked()
				_ = d3.Status()
			}
		}(i)
	}
	wg.Wait()
}

func TestDeadboltCandidateTokenBoundAndTailSmuggling(t *testing.T) {
	assert.Equal(t, 24, maxCandidateTokens)

	tenWords := "one two three four five six seven eight nine ten"
	tenHash := NormalizePhrase(tenWords)
	assert.True(t, VerifyPassphrase("my spoken passphrase is "+tenWords, tenHash))
	assert.True(t, VerifyPassphrase("hey assistant my spoken passphrase is "+tenWords+" please", tenHash))

	secret := "correct horse battery staple"
	secretHash := NormalizePhrase(secret)
	singleSecret := "zebraviolet"
	singleHash := NormalizePhrase(singleSecret)

	// Construct unrelated unique words (35 and 200 words, plus hyphenated 40-word stream).
	makeNoise := func(count int, sep string) string {
		words := make([]string, count)
		for i := range count {
			words[i] = "noise" + string(rune('a'+(i%26))) + string(rune('0'+(i/26)%10))
		}
		return strings.Join(words, sep)
	}

	noise22 := makeNoise(22, " ")
	noise24 := makeNoise(24, " ")
	noise25 := makeNoise(25, " ")
	noise32 := makeNoise(32, " ")
	noise35 := makeNoise(35, " ")
	noise200 := makeNoise(200, " ")

	maxPerTokenSet := 1 + maxWrapperSeekOffset + maxCandidateTokens*maxSpanTokenLength - (maxSpanTokenLength*(maxSpanTokenLength-1))/2
	assert.Equal(t, 202, maxPerTokenSet)

	c35 := buildPassphraseCandidates(noise35)
	c200 := buildPassphraseCandidates(noise200)
	assert.LessOrEqual(t, len(c35), maxPerTokenSet)
	assert.LessOrEqual(t, len(c200), maxPerTokenSet)
	assert.Equal(t, len(c35), len(c200), "candidate count must stay O(1)-bounded above maxCandidateTokens")

	hyphenatedLong := strings.ReplaceAll(makeNoise(40, " "), "noise", "tok-")
	cHyphen := buildPassphraseCandidates(hyphenatedLong)
	assert.LessOrEqual(t, len(cHyphen), 2*maxPerTokenSet)

	// Tail-word smuggling past maxCandidateTokens must fail.
	assert.False(t, VerifyPassphrase(noise32+" "+secret, secretHash))
	assert.False(t, VerifyPassphrase("my spoken passphrase is "+noise25+" "+secret, secretHash))
	assert.False(t, VerifyPassphrase(noise24+" "+singleSecret, singleHash))
	assert.False(t, VerifyPassphrase(noise22+" "+secret, secretHash), "span straddling token 24 must be rejected")

	// Within maxCandidateTokens bound still succeeds.
	assert.True(t, VerifyPassphrase("please "+makeNoise(8, " ")+" "+secret, secretHash))

	// End-to-end Deadbolt.Unlock rejects smuggled tail secret and does not unlock or bump epoch.
	d := NewDeadbolt(DeadboltConfig{PassHash: secretHash})
	ok, _, reason := d.Unlock(noise35 + " " + secret)
	assert.False(t, ok)
	assert.Equal(t, "invalid passphrase", reason)
	assert.False(t, d.IsUnlocked())
	assert.Equal(t, uint64(0), d.UnlockEpoch())
}

func TestDeadboltStatusJSONCompatibility(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	d := NewDeadbolt(DeadboltConfig{
		PassHash:               NormalizePhrase("delta echo"),
		TTL:                    600 * time.Second,
		AllowLockedCronSummary: true,
	})
	d.now = func() time.Time { return now }

	ok, _, _ := d.Unlock("delta echo")
	require.True(t, ok)

	raw, err := json.Marshal(d.Status())
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Equal(t, true, decoded["enabled"])
	assert.Equal(t, true, decoded["unlocked"])
	assert.Equal(t, float64(600), decoded["remaining_seconds"])
	assert.Equal(t, float64(600), decoded["ttl_seconds"])
	assert.Equal(t, float64(0), decoded["failed_attempts"])
	assert.Equal(t, true, decoded["allow_locked_cron_summary"])
	assert.NotEmpty(t, decoded["expires_at"])
}
