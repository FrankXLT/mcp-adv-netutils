package security

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DeadboltConfig configures a Deadbolt voice/passphrase lock manager.
type DeadboltConfig struct {
	PassHash               string
	TTL                    time.Duration
	AllowLockedCronSummary bool
	StatePath              string
}

// DeadboltStatus describes the current state of the Deadbolt lock.
type DeadboltStatus struct {
	Enabled                bool      `json:"enabled"`
	Unlocked               bool      `json:"unlocked"`
	ExpiresAt              time.Time `json:"expires_at,omitempty"`
	RemainingSeconds       int64     `json:"remaining_seconds"`
	TTLSeconds             int64     `json:"ttl_seconds"`
	FailedAttempts         int       `json:"failed_attempts"`
	LockedOut              bool      `json:"locked_out"`
	LockedUntil            time.Time `json:"locked_until,omitempty"`
	AllowLockedCronSummary bool      `json:"allow_locked_cron_summary"`
}

// Deadbolt manages a thread-safe passphrase-gated unlock window with
// sliding TTL expiration, brute-force cooldown, and optional atomic persistence.
type Deadbolt struct {
	mu                     sync.RWMutex
	passHash               string
	ttl                    time.Duration
	allowLockedCronSummary bool
	statePath              string
	unlockedAt             time.Time
	unlockEpoch            uint64
	lastSavedAt            time.Time
	failedAttempts         int
	lockedUntil            time.Time
	now                    func() time.Time
}

type deadboltPersistedState struct {
	PassHashDigest string    `json:"pass_hash_digest,omitempty"`
	UnlockedAt     time.Time `json:"unlocked_at,omitempty"`
	UnlockEpoch    uint64    `json:"unlock_epoch,omitempty"`
	FailedAttempts int       `json:"failed_attempts,omitempty"`
	LockedUntil    time.Time `json:"locked_until,omitempty"`
}

const (
	// DefaultDeadboltTTL is the default sliding unlock window duration (30 minutes).
	DefaultDeadboltTTL = 1800 * time.Second
	// MinDeadboltTTL is the minimum enforced sliding unlock window duration (5 minutes).
	MinDeadboltTTL = 300 * time.Second
	// MaxDeadboltFailedAttempts is the number of consecutive failed unlock attempts before lockout.
	MaxDeadboltFailedAttempts = 5
	// DeadboltLockoutDuration is the base cooldown duration after reaching MaxDeadboltFailedAttempts.
	DeadboltLockoutDuration = 30 * time.Second

	maxBackoffShift      = 5
	maxCandidateTokens   = 24
	maxSpanTokenLength   = 10
	maxWrapperSeekOffset = 6
	sha256HexLength      = 64
	statePersistInterval = time.Second
)

// NewDeadbolt constructs a Deadbolt manager from cfg, applying default and
// minimum TTL bounds and loading any matching persisted state from cfg.StatePath.
func NewDeadbolt(cfg DeadboltConfig) *Deadbolt {
	d := &Deadbolt{
		passHash:               strings.ToLower(strings.TrimSpace(cfg.PassHash)),
		ttl:                    clampTTL(cfg.TTL),
		allowLockedCronSummary: cfg.AllowLockedCronSummary,
		statePath:              strings.TrimSpace(cfg.StatePath),
		now:                    time.Now,
	}
	d.loadState()
	return d
}

// NormalizePhrase lowercases phrase, strips all characters outside [a-z0-9],
// and returns the lowercase SHA-256 hex digest.
func NormalizePhrase(phrase string) string {
	sum := sha256.Sum256([]byte(keepASCIIAlnumLower(phrase)))
	return hex.EncodeToString(sum[:])
}

// VerifyPassphrase compares spoken against a 64-character SHA-256 hex digest
// using constant-time digest comparison. It accepts punctuation/case variance,
// strips optional spoken wrappers, and checks contiguous spans of 1..10 tokens.
func VerifyPassphrase(spoken, expectedHash string) bool {
	expectedBytes, ok := parseSHA256Hex(expectedHash)
	if !ok {
		return false
	}
	candidates := buildPassphraseCandidates(spoken)
	if len(candidates) == 0 {
		return false
	}

	matched := 0
	for _, candidate := range candidates {
		sum := sha256.Sum256([]byte(candidate))
		matched |= subtle.ConstantTimeCompare(sum[:], expectedBytes)
	}
	return matched == 1
}

// IsEnabled reports whether Deadbolt protection is active (PassHash is non-empty).
func (d *Deadbolt) IsEnabled() bool {
	if d == nil {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.passHash != ""
}

// AllowLockedCronSummary reports whether summary-only cron output is permitted while locked.
func (d *Deadbolt) AllowLockedCronSummary() bool {
	if d == nil {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.allowLockedCronSummary
}

// IsUnlocked checks whether the deadbolt is currently unlocked. If enabled and
// within the TTL window, it slides unlockedAt forward to the current time.
func (d *Deadbolt) IsUnlocked() bool {
	if d == nil {
		return true
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.passHash == "" {
		return true
	}
	if d.unlockedAt.IsZero() {
		return false
	}

	now := d.nowFn()
	if now.Sub(d.unlockedAt) >= clampTTL(d.ttl) {
		d.unlockedAt = time.Time{}
		d.rotateUnlockEpochLocked()
		d.saveStateLocked(now)
		return false
	}

	d.unlockedAt = now
	if d.lastSavedAt.IsZero() || now.Sub(d.lastSavedAt) >= statePersistInterval {
		d.saveStateLocked(now)
	}
	return true
}

// Unlock validates spoken against the configured passphrase hash, respecting
// brute-force cooldowns. It returns whether unlock succeeded, the expiration time,
// and a human-readable status reason.
func (d *Deadbolt) Unlock(spoken string) (bool, time.Time, string) {
	if d == nil {
		return true, time.Time{}, "deadbolt disabled"
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.passHash == "" {
		return true, time.Time{}, "deadbolt disabled"
	}

	now := d.nowFn()
	if !d.lockedUntil.IsZero() && now.Before(d.lockedUntil) {
		remaining := max(d.lockedUntil.Sub(now).Round(time.Second), time.Second)
		return false, time.Time{}, fmt.Sprintf("deadbolt attempts locked; retry in %s", remaining)
	}

	if VerifyPassphrase(spoken, d.passHash) {
		wasLocked := d.unlockedAt.IsZero() || now.Sub(d.unlockedAt) >= clampTTL(d.ttl) || d.unlockEpoch == 0
		d.failedAttempts = 0
		d.lockedUntil = time.Time{}
		d.unlockedAt = now
		if wasLocked {
			d.rotateUnlockEpochLocked()
		}
		d.saveStateLocked(now)
		return true, now.Add(clampTTL(d.ttl)), "unlocked"
	}

	d.failedAttempts++
	reason := "invalid passphrase"
	if d.failedAttempts >= MaxDeadboltFailedAttempts {
		shift := min(d.failedAttempts-MaxDeadboltFailedAttempts, maxBackoffShift)
		cooldown := DeadboltLockoutDuration << shift
		d.lockedUntil = now.Add(cooldown)
		reason = fmt.Sprintf("too many failed attempts; locked for %s", cooldown)
	}
	d.saveStateLocked(now)
	return false, time.Time{}, reason
}

// Lock immediately closes an active unlock window and persists the state if configured.
func (d *Deadbolt) Lock() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.passHash == "" {
		return
	}
	if !d.unlockedAt.IsZero() {
		d.rotateUnlockEpochLocked()
	}
	d.unlockedAt = time.Time{}
	d.saveStateLocked(d.nowFn())
}

// UnlockEpoch returns the current monotonic unlock epoch, or 0 if d is nil.
func (d *Deadbolt) UnlockEpoch() uint64 {
	if d == nil {
		return 0
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.unlockEpoch
}

// Status returns a read-only snapshot of the Deadbolt state without sliding TTL.
func (d *Deadbolt) Status() DeadboltStatus {
	if d == nil {
		return DeadboltStatus{Enabled: false, Unlocked: true, TTLSeconds: int64(DefaultDeadboltTTL.Seconds())}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := d.nowFn()
	ttl := clampTTL(d.ttl)
	enabled := d.passHash != ""
	status := DeadboltStatus{
		Enabled:                enabled,
		Unlocked:               !enabled,
		TTLSeconds:             int64(ttl.Seconds()),
		FailedAttempts:         d.failedAttempts,
		AllowLockedCronSummary: d.allowLockedCronSummary,
	}
	if enabled && !d.unlockedAt.IsZero() && now.Sub(d.unlockedAt) < ttl {
		expiresAt := d.unlockedAt.Add(ttl)
		status.Unlocked = true
		status.ExpiresAt = expiresAt
		status.RemainingSeconds = int64(expiresAt.Sub(now).Seconds())
	}
	if !d.lockedUntil.IsZero() && now.Before(d.lockedUntil) {
		status.LockedOut = true
		status.LockedUntil = d.lockedUntil
	}
	return status
}

func (d *Deadbolt) rotateUnlockEpochLocked() {
	d.unlockEpoch++
	if d.unlockEpoch == 0 {
		d.unlockEpoch = 1
	}
}

func (d *Deadbolt) nowFn() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}

func clampTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return DefaultDeadboltTTL
	}
	if ttl < MinDeadboltTTL {
		return MinDeadboltTTL
	}
	return ttl
}

func (d *Deadbolt) passHashFingerprint() string {
	sum := sha256.Sum256([]byte(d.passHash))
	return hex.EncodeToString(sum[:])
}

func (d *Deadbolt) loadState() {
	if d.statePath == "" || d.passHash == "" {
		return
	}

	cleanPath := filepath.Clean(d.statePath)
	// #nosec G304 -- statePath is an administrator-configured local file path.
	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		return
	}

	var state deadboltPersistedState
	if err := json.Unmarshal(raw, &state); err != nil {
		return
	}

	if state.PassHashDigest != d.passHashFingerprint() {
		return
	}

	d.unlockedAt = state.UnlockedAt
	d.unlockEpoch = state.UnlockEpoch
	if !d.unlockedAt.IsZero() && d.unlockEpoch == 0 {
		d.unlockEpoch = 1
	}
	d.failedAttempts = state.FailedAttempts
	d.lockedUntil = state.LockedUntil
}

func (d *Deadbolt) saveStateLocked(now time.Time) {
	if d.statePath == "" || d.passHash == "" {
		return
	}

	data, err := json.Marshal(deadboltPersistedState{
		PassHashDigest: d.passHashFingerprint(),
		UnlockedAt:     d.unlockedAt,
		UnlockEpoch:    d.unlockEpoch,
		FailedAttempts: d.failedAttempts,
		LockedUntil:    d.lockedUntil,
	})
	if err != nil {
		return
	}

	if writeFileAtomic(filepath.Clean(d.statePath), data) == nil {
		d.lastSavedAt = now
	}
}

func writeFileAtomic(cleanPath string, data []byte) error {
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".deadbolt-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}

	tmpName := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp state file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp state file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp state file: %w", err)
	}
	if err := os.Rename(tmpName, cleanPath); err != nil {
		return fmt.Errorf("rename state file: %w", err)
	}

	renamed = true
	return nil
}

func parseSHA256Hex(raw string) ([]byte, bool) {
	clean := strings.ToLower(strings.TrimSpace(raw))
	if len(clean) != sha256HexLength {
		return nil, false
	}

	decoded, err := hex.DecodeString(clean)
	if err != nil || len(decoded) != sha256.Size {
		return nil, false
	}

	return decoded, true
}

func keepASCIIAlnumLower(s string) string {
	lower := strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(lower))
	for _, r := range lower {
		if isASCIIAlnum(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isASCIIAlnum(r rune) bool {
	return ('a' <= r && r <= 'z') || ('0' <= r && r <= '9')
}

func tokenizeAlnum(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !isASCIIAlnum(r)
	})
}

func tokenizeFieldsAlnum(s string) []string {
	fields := strings.Fields(s)
	tokens := make([]string, 0, len(fields))
	for _, field := range fields {
		if cleaned := keepASCIIAlnumLower(field); cleaned != "" {
			tokens = append(tokens, cleaned)
		}
	}
	return tokens
}

func buildPassphraseCandidates(spoken string) []string {
	alnumTokens := tokenizeAlnum(spoken)
	fieldTokens := tokenizeFieldsAlnum(spoken)
	if len(alnumTokens) == 0 && len(fieldTokens) == 0 {
		return nil
	}

	seen := make(map[string]struct{})
	candidates := make([]string, 0, 16)
	addCandidate := func(c string) {
		if c == "" {
			return
		}
		if _, exists := seen[c]; !exists {
			seen[c] = struct{}{}
			candidates = append(candidates, c)
		}
	}

	addTokenSetCandidates(alnumTokens, addCandidate)
	addTokenSetCandidates(fieldTokens, addCandidate)
	return candidates
}

func addTokenSetCandidates(tokens []string, addCandidate func(string)) {
	if len(tokens) == 0 {
		return
	}
	addCandidate(strings.Join(tokens, ""))

	maxOffset := min(len(tokens), maxWrapperSeekOffset)
	for offset := range maxOffset {
		if stripped := stripLeadingSpokenWrappers(tokens[offset:]); len(stripped) > 0 {
			addCandidate(strings.Join(stripped, ""))
		}
	}

	scanLimit := min(len(tokens), maxCandidateTokens)
	limited := tokens[:scanLimit]
	for start := range scanLimit {
		maxSpan := min(maxSpanTokenLength, scanLimit-start)
		var joined strings.Builder
		for spanLen := range maxSpan {
			joined.WriteString(limited[start+spanLen])
			addCandidate(joined.String())
		}
	}
}

func stripLeadingSpokenWrappers(tokens []string) []string {
	idx := 0
	if idx < len(tokens) && (tokens[idx] == "my" || tokens[idx] == "the") {
		idx++
	}
	if idx < len(tokens) && (tokens[idx] == "spoken" || tokens[idx] == "voice") {
		idx++
	}

	nounIdx := idx
	for idx < len(tokens) && isWrapperNoun(tokens[idx]) {
		idx++
	}
	if idx == nounIdx {
		return nil
	}
	if idx < len(tokens) && tokens[idx] == "is" {
		idx++
	}
	if idx >= len(tokens) {
		return nil
	}
	return tokens[idx:]
}

func isWrapperNoun(token string) bool {
	return token == "passphrase" || token == "password" || token == "passcode" ||
		token == "code" || token == "secret" || token == "key"
}
