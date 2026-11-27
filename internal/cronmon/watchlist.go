// Package cronmon implements scheduled watchlist execution, Two-Tick Alert Hysteresis,
// and compact cron health status rendering.
package cronmon

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/robfig/cron/v3"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

// WatchItem defines a single scheduled probe or diagnostic recipe entry.
type WatchItem struct {
	Key            string         `yaml:"key" json:"key"`
	Schedule       string         `yaml:"schedule" json:"schedule"`
	Tool           string         `yaml:"tool" json:"tool"`
	Target         string         `yaml:"target" json:"target"`
	Args           map[string]any `yaml:"args,omitempty" json:"args,omitempty"`
	Enabled        bool           `yaml:"enabled" json:"enabled"`
	TimeoutSeconds int            `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
}

// WatchlistFile represents the persisted YAML watchlist configuration.
type WatchlistFile struct {
	Version    int         `yaml:"version" json:"version"`
	WebhookURL string      `yaml:"webhook_url,omitempty" json:"webhook_url,omitempty"`
	Items      []WatchItem `yaml:"items" json:"items"`
}

// RunResult captures the normalized outcome returned by a RunnerFunc execution.
type RunResult struct {
	Status       string `json:"status"`
	Summary      string `json:"summary"`
	ASCIIDefault string `json:"ascii_default"`
	PayloadJSON  string `json:"payload_json"`
	DurationMS   int64  `json:"duration_ms"`
}

// RunnerFunc executes a single watchlist item and returns its diagnostic result.
//
//nolint:gocritic // hugeParam: WatchItem value signature preserves RunnerFunc contract.
type RunnerFunc func(ctx context.Context, item WatchItem) (*RunResult, error)

// SchedulerConfig configures a cronmon Scheduler instance.
type SchedulerConfig struct {
	Store         *store.JobStore
	WatchlistPath string
	Watchlist     *WatchlistFile
	Runner        RunnerFunc
	HTTPClient    *http.Client
	Guard         *security.TargetGuard
	NowFunc       func() time.Time
}

// Scheduler coordinates recurring cron watchlist execution, manual runs,
// watchlist hot-reloading, and Two-Tick Alert Hysteresis persistence.
type Scheduler struct {
	cron          *cron.Cron
	store         *store.JobStore
	watchlistPath string
	watchlist     *WatchlistFile
	runner        RunnerFunc
	httpClient    *http.Client
	guard         *security.TargetGuard
	nowFunc       func() time.Time
	entryIDs      map[string]cron.EntryID
	mu            sync.RWMutex
	started       bool
	runCtx        context.Context
	runCancel     context.CancelFunc
	wg            sync.WaitGroup
}

const (
	defaultWebhookTimeout = 10 * time.Second
	defaultItemTimeout    = 60 * time.Second
	runOnceConcurrency    = 4
	maxWebhookRedirects   = 5
	watchlistFilePerm     = 0o600
	watchlistDirPerm      = 0o750
)

var (
	// ErrItemNotFound indicates the requested watchlist key does not exist.
	ErrItemNotFound = errors.New("watchlist item not found")
	// ErrInvalidWatchlist indicates watchlist validation failed.
	ErrInvalidWatchlist = errors.New("invalid watchlist")
)

// UnmarshalYAML decodes either canonical "key" or legacy "id" watchlist item fields.
func (w *WatchItem) UnmarshalYAML(value *yaml.Node) error {
	var m struct {
		Key            string         `yaml:"key"`
		ID             string         `yaml:"id"`
		Schedule       string         `yaml:"schedule"`
		Tool           string         `yaml:"tool"`
		Target         string         `yaml:"target"`
		Args           map[string]any `yaml:"args"`
		Enabled        bool           `yaml:"enabled"`
		TimeoutSeconds int            `yaml:"timeout_seconds"`
	}
	if err := value.Decode(&m); err != nil {
		return fmt.Errorf("decode watch item: %w", err)
	}
	key := strings.TrimSpace(m.Key)
	if key == "" {
		key = strings.TrimSpace(m.ID)
	}
	*w = WatchItem{
		Key: key, Schedule: strings.TrimSpace(m.Schedule), Tool: strings.TrimSpace(m.Tool),
		Target: strings.TrimSpace(m.Target), Args: cloneAnyMap(m.Args), Enabled: m.Enabled, TimeoutSeconds: m.TimeoutSeconds,
	}
	return nil
}

// UnmarshalYAML decodes either canonical "items" or legacy "jobs" watchlist collections.
func (wf *WatchlistFile) UnmarshalYAML(value *yaml.Node) error {
	var raw struct {
		Version    int         `yaml:"version"`
		WebhookURL string      `yaml:"webhook_url"`
		Items      []WatchItem `yaml:"items"`
		Jobs       []WatchItem `yaml:"jobs"`
	}
	if err := value.Decode(&raw); err != nil {
		return fmt.Errorf("decode watchlist file: %w", err)
	}
	items := raw.Items
	if len(items) == 0 && len(raw.Jobs) > 0 {
		items = raw.Jobs
	}
	*wf = WatchlistFile{Version: raw.Version, WebhookURL: strings.TrimSpace(raw.WebhookURL), Items: cloneWatchItems(items)}
	return nil
}

// LoadWatchlist reads, parses, and validates a YAML watchlist file.
func LoadWatchlist(path string) (*WatchlistFile, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return nil, fmt.Errorf("%w: watchlist path must not be empty", ErrInvalidWatchlist)
	}
	cleanPath = filepath.Clean(cleanPath)
	// #nosec G304 -- watchlist path is a local configuration file path.
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("read watchlist %q: %w", cleanPath, err)
	}
	var wl WatchlistFile
	if err := yaml.Unmarshal(data, &wl); err != nil {
		return nil, fmt.Errorf("parse watchlist %q: %w", cleanPath, err)
	}
	if err := ValidateWatchlist(&wl); err != nil {
		return nil, err
	}
	return &wl, nil
}

// SaveWatchlist validates and atomically writes a YAML watchlist file with 0600 permissions.
func SaveWatchlist(path string, wl *WatchlistFile) error {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return fmt.Errorf("%w: watchlist path must not be empty", ErrInvalidWatchlist)
	}
	if err := ValidateWatchlist(wl); err != nil {
		return err
	}
	data, err := yaml.Marshal(wl)
	if err != nil {
		return fmt.Errorf("marshal watchlist: %w", err)
	}
	return writeFileAtomic(filepath.Clean(cleanPath), data)
}

// ValidateWatchlist verifies watchlist structure, unique item keys, and standard cron expressions.
func ValidateWatchlist(wl *WatchlistFile) error {
	if wl == nil {
		return fmt.Errorf("%w: watchlist must not be nil", ErrInvalidWatchlist)
	}
	if strings.TrimSpace(wl.WebhookURL) != "" {
		if _, err := validateWebhookSyntax(wl.WebhookURL); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidWatchlist, err)
		}
	}
	seen := make(map[string]struct{}, len(wl.Items))
	for i := range wl.Items {
		item := &wl.Items[i]
		key, sched := strings.TrimSpace(item.Key), strings.TrimSpace(item.Schedule)
		switch {
		case key == "":
			return fmt.Errorf("%w: item at index %d has empty key", ErrInvalidWatchlist, i)
		case sched == "":
			return fmt.Errorf("%w: item %q has empty schedule", ErrInvalidWatchlist, key)
		case strings.TrimSpace(item.Tool) == "":
			return fmt.Errorf("%w: item %q has empty tool", ErrInvalidWatchlist, key)
		case item.TimeoutSeconds < 0:
			return fmt.Errorf("%w: item %q timeout_seconds must be >= 0", ErrInvalidWatchlist, key)
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: duplicate key %q", ErrInvalidWatchlist, key)
		}
		seen[key] = struct{}{}
		if _, err := cron.ParseStandard(sched); err != nil {
			return fmt.Errorf("%w: item %q invalid schedule %q: %w", ErrInvalidWatchlist, key, sched, err)
		}
	}
	return nil
}

// NewScheduler constructs a Scheduler backed by JobStore, RunnerFunc, and TargetGuard.
func NewScheduler(cfg *SchedulerConfig) (*Scheduler, error) {
	if cfg == nil || cfg.Store == nil || cfg.Runner == nil {
		return nil, errors.New("scheduler config, store, and runner must not be nil")
	}
	wlPath, wl, err := strings.TrimSpace(cfg.WatchlistPath), &WatchlistFile{Version: 1}, error(nil)
	if cfg.Watchlist != nil {
		wl = cloneWatchlist(cfg.Watchlist)
		err = ValidateWatchlist(wl)
	} else if wlPath != "" {
		wl, err = LoadWatchlist(wlPath)
	}
	if err != nil {
		return nil, err
	}
	guard := cfg.Guard
	if guard == nil {
		if guard, err = security.NewTargetGuard(nil, nil); err != nil {
			return nil, fmt.Errorf("init default target guard: %w", err)
		}
	}
	client, nowFn := cfg.HTTPClient, cfg.NowFunc
	if client == nil {
		client = newDefaultHTTPClient(guard)
	}
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	s := &Scheduler{
		cron: newCronEngine(), store: cfg.Store, watchlistPath: wlPath, watchlist: wl,
		runner: cfg.Runner, httpClient: client, guard: guard, nowFunc: nowFn,
		entryIDs: make(map[string]cron.EntryID),
	}
	if err := s.syncEntriesLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// Start activates the internal robfig/cron/v3 scheduler and watches ctx for cancellation.
func (s *Scheduler) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	if s.cron == nil {
		s.cron = newCronEngine()
		if err := s.syncEntriesLocked(); err != nil {
			s.mu.Unlock()
			return err
		}
	}
	stopCtx := context.WithoutCancel(ctx)
	watchCtx, watchCancel := context.WithCancel(ctx)
	tickCtx, tickCancel := context.WithCancel(stopCtx)
	s.runCtx, s.started = tickCtx, true
	s.runCancel = func() {
		watchCancel()
		tickCancel()
	}
	s.cron.Start()
	s.wg.Go(func() {
		<-watchCtx.Done()
		_ = s.stopInternal(stopCtx)
	})
	s.mu.Unlock()
	return nil
}

// Stop halts the cron scheduler, waits for running jobs up to ctx deadline, and cleans up resources.
func (s *Scheduler) Stop(ctx context.Context) error {
	err := s.stopInternal(ctx)
	s.wg.Wait()
	return err
}

// Reload reloads the watchlist from disk (if WatchlistPath is configured) and hot-swaps cron entries.
func (s *Scheduler) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.watchlistPath != "" {
		fresh, err := LoadWatchlist(s.watchlistPath)
		if err != nil {
			return err
		}
		s.watchlist = fresh
	} else if err := ValidateWatchlist(s.watchlist); err != nil {
		return err
	}
	if s.cron == nil {
		s.cron = newCronEngine()
	}
	return s.syncEntriesLocked()
}

// RunOnce executes all enabled watchlist items concurrently (bounded to 4 workers) for systemd timer mode.
func (s *Scheduler) RunOnce(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}
	s.mu.RLock()
	items := cloneWatchItems(s.watchlist.Items)
	s.mu.RUnlock()
	var eg errgroup.Group
	eg.SetLimit(runOnceConcurrency)
	for i := range items {
		if !items[i].Enabled {
			continue
		}
		item := items[i]
		eg.Go(func() error {
			_, err := s.executeAndRecord(ctx, &item)
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		return fmt.Errorf("run watchlist once: %w", err)
	}
	return nil
}

// RunItemNow immediately runs a single watchlist item identified by key and updates its hysteresis state.
func (s *Scheduler) RunItemNow(ctx context.Context, key string) (store.CronStateRecord, error) {
	if ctx == nil {
		return store.CronStateRecord{}, errors.New("context must not be nil")
	}
	trimmedKey := strings.TrimSpace(key)
	if trimmedKey == "" {
		return store.CronStateRecord{}, fmt.Errorf("%w: key must not be empty", ErrItemNotFound)
	}
	s.mu.RLock()
	idx := findItemIndex(s.watchlist.Items, trimmedKey)
	if idx < 0 {
		s.mu.RUnlock()
		return store.CronStateRecord{}, fmt.Errorf("%w: %q", ErrItemNotFound, trimmedKey)
	}
	item := cloneWatchItem(&s.watchlist.Items[idx])
	s.mu.RUnlock()
	return s.executeAndRecord(ctx, &item)
}

func newCronEngine() *cron.Cron {
	return cron.New(cron.WithChain(cron.SkipIfStillRunning(cron.DefaultLogger), cron.Recover(cron.DefaultLogger)))
}

func (s *Scheduler) stopInternal(ctx context.Context) error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = false
	cronInst, cancel := s.cron, s.runCancel
	s.cron, s.runCancel = nil, nil
	s.mu.Unlock()

	var ctxDone <-chan struct{}
	if ctx != nil {
		ctxDone = ctx.Done()
	}
	cronDone := cronInst.Stop()
	var stopErr error
	select {
	case <-cronDone.Done():
	case <-ctxDone:
		stopErr = fmt.Errorf("stop cron scheduler: %w", ctx.Err())
	}
	if cancel != nil {
		cancel()
	}
	return stopErr
}

func (s *Scheduler) syncEntriesLocked() error {
	if s.cron == nil {
		return nil
	}
	for _, entry := range s.cron.Entries() {
		s.cron.Remove(entry.ID)
	}
	s.entryIDs = make(map[string]cron.EntryID)
	for i := range s.watchlist.Items {
		if !s.watchlist.Items[i].Enabled {
			continue
		}
		item := cloneWatchItem(&s.watchlist.Items[i])
		id, err := s.cron.AddFunc(item.Schedule, func() { s.runScheduledItem(item) })
		if err != nil {
			return fmt.Errorf("schedule watchlist item %q (%q): %w", item.Key, item.Schedule, err)
		}
		s.entryIDs[item.Key] = id
	}
	return nil
}

//nolint:gocritic // hugeParam: cron callback captures an immutable WatchItem value snapshot.
func (s *Scheduler) runScheduledItem(item WatchItem) {
	s.mu.RLock()
	ctx := s.runCtx
	s.mu.RUnlock()
	if ctx == nil {
		return
	}
	_, _ = s.executeAndRecord(ctx, &item)
}

func writeFileAtomic(cleanPath string, data []byte) error {
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, watchlistDirPerm); err != nil {
		return fmt.Errorf("create watchlist directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".watchlist-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp watchlist file: %w", err)
	}
	tmpName := tmp.Name()
	var writeErr error
	if writeErr = tmp.Chmod(watchlistFilePerm); writeErr == nil {
		if _, writeErr = tmp.Write(data); writeErr == nil {
			writeErr = tmp.Sync()
		}
	}
	if closeErr := tmp.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp watchlist file: %w", writeErr)
	}
	if err := os.Rename(tmpName, cleanPath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename temp watchlist file: %w", err)
	}
	return nil
}

func cloneWatchlist(wl *WatchlistFile) *WatchlistFile {
	if wl == nil {
		return &WatchlistFile{Version: 1}
	}
	return &WatchlistFile{Version: wl.Version, WebhookURL: wl.WebhookURL, Items: cloneWatchItems(wl.Items)}
}

func cloneWatchItems(items []WatchItem) []WatchItem {
	if len(items) == 0 {
		return nil
	}
	out := make([]WatchItem, len(items))
	for i := range items {
		out[i] = cloneWatchItem(&items[i])
	}
	return out
}

func cloneWatchItem(item *WatchItem) WatchItem {
	cp := *item
	cp.Args = cloneAnyMap(item.Args)
	return cp
}

func cloneAnyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := maps.Clone(src)
	for k, v := range dst {
		switch val := v.(type) {
		case map[string]any:
			dst[k] = cloneAnyMap(val)
		case []any:
			dst[k] = append([]any(nil), val...)
		}
	}
	return dst
}
