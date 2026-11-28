package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // Pure-Go SQLite driver (CGO_ENABLED=0).
)

// JobRecord represents a persisted diagnostic or scheduled cron execution.
type JobRecord struct {
	JobID        string `json:"job_id"`
	ToolName     string `json:"tool_name"`
	Target       string `json:"target"`
	Source       string `json:"source"`
	Status       string `json:"status"`
	Summary      string `json:"summary"`
	PayloadJSON  string `json:"payload_json"`
	ASCIIDefault string `json:"ascii_default"`
	DurationMS   int64  `json:"duration_ms"`
	CreatedAt    int64  `json:"created_at"`
	ExpiresAt    int64  `json:"expires_at"`
	IsIncident   bool   `json:"is_incident"`
	DownAged     bool   `json:"down_aged"`
}

// CronStateRecord tracks the current hysteresis and alert state of a cron check.
type CronStateRecord struct {
	JobKey           string `json:"job_key"`
	ToolName         string `json:"tool_name"`
	Target           string `json:"target"`
	ConsecutiveNonOK int    `json:"consecutive_non_ok"`
	ActiveAlert      bool   `json:"active_alert"`
	LastStatus       string `json:"last_status"`
	LastTickAt       int64  `json:"last_tick_at"`
	LastAlertFlipAt  int64  `json:"last_alert_flip_at"`
	LastJobID        string `json:"last_job_id"`
	LastSummary      string `json:"last_summary"`
}

// CronDailyStat represents aggregated daily cron metrics for a job key.
type CronDailyStat struct {
	DayUTC        string  `json:"day_utc"`
	JobKey        string  `json:"job_key"`
	OKCount       int64   `json:"ok_count"`
	WarnCount     int64   `json:"warn_count"`
	FailCount     int64   `json:"fail_count"`
	AvgDurationMS float64 `json:"avg_duration_ms"`
	UpdatedAt     int64   `json:"updated_at"`
}

// CronSummary holds current cron states and daily rollup/tick buckets for a window.
type CronSummary struct {
	Period     string            `json:"period"`
	Since      int64             `json:"since"`
	States     []CronStateRecord `json:"states"`
	DailyStats []CronDailyStat   `json:"daily_stats"`
}

// SnapshotRecord represents a named baseline or diagnostic snapshot.
type SnapshotRecord struct {
	Name        string `json:"name"`
	JobID       string `json:"job_id"`
	Target      string `json:"target"`
	PayloadJSON string `json:"payload_json"`
	CreatedAt   int64  `json:"created_at"`
}

// JobFilter specifies optional filters and pagination for ListJobs.
type JobFilter struct {
	ToolName       string
	Target         string
	TargetContains string
	Source         string
	Status         string
	Since          int64
	Until          int64
	Limit          int
	Offset         int
	IncidentsOnly  bool
}

// StoreStats reports row counts, disk usage, and SQLite pragma metrics.
type StoreStats struct {
	DBPath           string `json:"db_path"`
	JobCount         int64  `json:"job_count"`
	IncidentCount    int64  `json:"incident_count"`
	CronStateCount   int64  `json:"cron_state_count"`
	DailyRollupRows  int64  `json:"daily_rollup_rows"`
	SnapshotCount    int64  `json:"snapshot_count"`
	DestinationCount int64  `json:"destination_count"`
	DBSizeBytes      int64  `json:"db_size_bytes"`
	MaxStoreBytes    int64  `json:"max_store_bytes"`
	PageSize         int64  `json:"page_size"`
	PageCount        int64  `json:"page_count"`
	FreelistCount    int64  `json:"freelist_count"`
	JournalMode      string `json:"journal_mode"`
	AutoVacuum       int64  `json:"auto_vacuum"`
}

// JobStore manages SQLite persistence for jobs, cron state, rollups, and snapshots.
type JobStore struct {
	dbPath        string
	filePath      string
	rwDB          *sql.DB
	roDB          *sql.DB
	separateRO    bool
	maxStoreBytes int64
	reaperMu      sync.Mutex
	closed        bool
	baseCtx       context.Context
	baseCancel    context.CancelFunc
	wg            sync.WaitGroup
}

type rowScanner interface {
	Scan(dest ...any) error
}

const (
	defaultListLimit  = 100
	bytesPerMegabyte  = 1024 * 1024
	jobIDRandByteSize = 6

	schemaDDL = `
CREATE TABLE IF NOT EXISTS jobs (job_id TEXT PRIMARY KEY, tool_name TEXT NOT NULL, target TEXT NOT NULL, source TEXT NOT NULL, status TEXT NOT NULL, summary TEXT NOT NULL, payload_json TEXT NOT NULL, ascii_default TEXT NOT NULL, duration_ms INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, is_incident INTEGER NOT NULL DEFAULT 0, down_aged INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS cron_state (job_key TEXT PRIMARY KEY, tool_name TEXT NOT NULL, target TEXT NOT NULL, consecutive_non_ok INTEGER NOT NULL DEFAULT 0, active_alert INTEGER NOT NULL DEFAULT 0, last_status TEXT NOT NULL, last_tick_at INTEGER NOT NULL, last_alert_flip_at INTEGER NOT NULL DEFAULT 0, last_job_id TEXT NOT NULL, last_summary TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cron_daily_rollups (day_utc TEXT NOT NULL, job_key TEXT NOT NULL, ok_count INTEGER NOT NULL, warn_count INTEGER NOT NULL, fail_count INTEGER NOT NULL, avg_duration_ms REAL NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (day_utc, job_key));
CREATE TABLE IF NOT EXISTS snapshots (name TEXT PRIMARY KEY, job_id TEXT NOT NULL, target TEXT NOT NULL, payload_json TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS saved_destinations (id TEXT PRIMARY KEY, name TEXT NOT NULL, target TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'Core', mac TEXT NOT NULL DEFAULT '', default_check TEXT NOT NULL DEFAULT 'recipe_diff_ping', pinned INTEGER NOT NULL DEFAULT 0, monitor_enabled INTEGER NOT NULL DEFAULT 0, monitor_schedule TEXT NOT NULL DEFAULT '*/5 * * * *', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_expires_at ON jobs(expires_at);
CREATE INDEX IF NOT EXISTS idx_jobs_source_created ON jobs(source, created_at);
CREATE INDEX IF NOT EXISTS idx_saved_destinations_pinned ON saved_destinations(pinned DESC, updated_at DESC);`
	insertJobSQL = `INSERT INTO jobs (job_id, tool_name, target, source, status, summary, payload_json, ascii_default, duration_ms, created_at, expires_at, is_incident, down_aged) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(job_id) DO UPDATE SET tool_name=excluded.tool_name, target=excluded.target, source=excluded.source, status=excluded.status, summary=excluded.summary, payload_json=excluded.payload_json, ascii_default=excluded.ascii_default, duration_ms=excluded.duration_ms, created_at=excluded.created_at, expires_at=excluded.expires_at, is_incident=excluded.is_incident, down_aged=excluded.down_aged;`
	getJobSQL    = `SELECT job_id, tool_name, target, source, status, summary, payload_json, ascii_default, duration_ms, created_at, expires_at, is_incident, down_aged FROM jobs WHERE job_id = ?;`
	listJobsSQL  = `SELECT job_id, tool_name, target, source, status, summary, payload_json, ascii_default, duration_ms, created_at, expires_at, is_incident, down_aged FROM jobs WHERE ` + jobFilterWhereClause + ` ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?;`
)

var (
	// ErrNotFound indicates the requested record does not exist in the store.
	ErrNotFound = errors.New("record not found")
	// ErrInvalidPeriod indicates an unsupported period string was passed to GetCronStatus.
	ErrInvalidPeriod = errors.New("invalid cron status period")
)

// Open initializes a WAL-backed SQLite JobStore with a dedicated read-write pool
// and a separate read-only (?mode=ro) pool for concurrent queries on disk paths.
func Open(ctx context.Context, dbPath string, maxStoreMB int) (*JobStore, error) {
	trimmed := strings.TrimSpace(dbPath)
	if trimmed == "" {
		return nil, errors.New("dbPath must not be empty")
	}
	if maxStoreMB <= 0 {
		maxStoreMB = DefaultMaxStoreMB
	}
	rwDSN, roDSN, filePath, separateRO, err := resolveDSNs(trimmed)
	if err != nil {
		return nil, err
	}
	if filePath != "" {
		if mkErr := os.MkdirAll(filepath.Dir(filePath), 0o750); mkErr != nil {
			return nil, fmt.Errorf("create store directory: %w", mkErr)
		}
	}

	rwDB, err := openPool(ctx, rwDSN, 1, true)
	if err != nil {
		return nil, err
	}
	roDB := rwDB
	if separateRO {
		if roDB, err = openPool(ctx, roDSN, 4, false); err != nil {
			_ = rwDB.Close()
			return nil, err
		}
	}
	baseCtx, baseCancel := context.WithCancel(context.Background())
	return &JobStore{
		dbPath: trimmed, filePath: filePath, rwDB: rwDB, roDB: roDB,
		separateRO: separateRO, maxStoreBytes: int64(maxStoreMB) * bytesPerMegabyte,
		baseCtx: baseCtx, baseCancel: baseCancel,
	}, nil
}

func resolveDSNs(dbPath string) (string, string, string, bool, error) {
	if dbPath == ":memory:" {
		return dbPath, "", "", false, nil
	}
	if strings.HasPrefix(dbPath, "file:") {
		u, err := url.Parse(dbPath)
		if err != nil {
			return "", "", "", false, fmt.Errorf("parse sqlite file URI: %w", err)
		}
		if strings.EqualFold(u.Query().Get("mode"), "memory") {
			return dbPath, "", "", false, nil
		}
		filePath := u.Path
		if filePath == "" {
			filePath = u.Opaque
		}
		rwU, roU := *u, *u
		rwQ, roQ := rwU.Query(), roU.Query()
		if !rwQ.Has("_txlock") {
			rwQ.Set("_txlock", "immediate")
		}
		roQ.Set("mode", "ro")
		roQ.Set("_busy_timeout", "5000")
		roQ.Set("_query_only", "true")
		rwU.RawQuery, roU.RawQuery = rwQ.Encode(), roQ.Encode()
		return rwU.String(), roU.String(), filePath, true, nil
	}
	absPath, err := filepath.Abs(filepath.Clean(dbPath))
	if err != nil {
		return "", "", "", false, fmt.Errorf("resolve absolute db path: %w", err)
	}
	slash := filepath.ToSlash(absPath)
	rwURI := (&url.URL{Scheme: "file", Path: slash, RawQuery: "_txlock=immediate"}).String()
	roURI := (&url.URL{Scheme: "file", Path: slash, RawQuery: "mode=ro&_busy_timeout=5000&_query_only=true"}).String()
	return rwURI, roURI, absPath, true, nil
}

func openPool(ctx context.Context, dsn string, maxConns int, initSchema bool) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite db: %w", err)
	}
	if !initSchema {
		return db, nil
	}
	// Apply auto_vacuum=INCREMENTAL before journal_mode=WAL or DDL materializes page 1.
	for _, stmt := range []string{"PRAGMA auto_vacuum=INCREMENTAL;", "PRAGMA journal_mode=WAL;", "PRAGMA synchronous=NORMAL;", "PRAGMA busy_timeout=5000;", schemaDDL} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("init sqlite schema/pragma: %w", err)
		}
	}
	return db, nil
}

// Close cancels background reaper activity and closes SQLite database pools.
func (s *JobStore) Close() error {
	s.reaperMu.Lock()
	if s.closed {
		s.reaperMu.Unlock()
		return nil
	}
	s.closed = true
	s.baseCancel()
	s.reaperMu.Unlock()
	s.wg.Wait()

	var errs []error
	if s.separateRO && s.roDB != nil {
		if err := s.roDB.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close read-only db: %w", err))
		}
	}
	if s.rwDB != nil {
		if err := s.rwDB.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close read-write db: %w", err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("close job store: %w", errors.Join(errs...))
	}
	return nil
}

// SaveJob persists a JobRecord, generating a job_id and 30d expires_at if unset.
func (s *JobStore) SaveJob(ctx context.Context, rec *JobRecord) error {
	if rec == nil {
		return errors.New("job record must not be nil")
	}
	if rec.CreatedAt == 0 {
		rec.CreatedAt = time.Now().UTC().Unix()
	}
	if rec.ExpiresAt == 0 {
		rec.ExpiresAt = rec.CreatedAt + int64(DefaultRetention.Seconds())
	}
	if rec.JobID == "" {
		id, err := generateJobID(rec.CreatedAt)
		if err != nil {
			return err
		}
		rec.JobID = id
	}
	if _, err := s.rwDB.ExecContext(ctx, insertJobSQL,
		rec.JobID, rec.ToolName, rec.Target, rec.Source, rec.Status, rec.Summary,
		rec.PayloadJSON, rec.ASCIIDefault, rec.DurationMS, rec.CreatedAt, rec.ExpiresAt,
		boolToInt(rec.IsIncident), boolToInt(rec.DownAged),
	); err != nil {
		return fmt.Errorf("save job %q: %w", rec.JobID, err)
	}
	return nil
}

// GetJob retrieves a single JobRecord by job_id using the read-only pool.
func (s *JobStore) GetJob(ctx context.Context, jobID string) (*JobRecord, error) {
	rec, err := scanJob(s.roDB.QueryRowContext(ctx, getJobSQL, jobID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("job %q (%w): %w", jobID, ErrNotFound, err)
		}
		return nil, fmt.Errorf("get job %q: %w", jobID, err)
	}
	return rec, nil
}

// ListJobs queries jobs matching the provided filter ordered newest first.
//
//nolint:gocritic // hugeParam: value filter matches JobStore contract.
func (s *JobStore) ListJobs(ctx context.Context, filter JobFilter) ([]JobRecord, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = defaultListLimit
	}
	args := append(jobFilterArgs(filter), limit, max(filter.Offset, 0))
	rows, err := s.roDB.QueryContext(ctx, listJobsSQL, args...)
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	defer rows.Close()

	var jobs []JobRecord
	for rows.Next() {
		rec, scanErr := scanJob(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		jobs = append(jobs, *rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate job rows: %w", err)
	}
	return jobs, nil
}

// RecordCronTick updates cron_state using Two-Tick Alert Hysteresis.
// active_alert flips to true only after consecutive_non_ok >= 2, and resets to false on OK.
func (s *JobStore) RecordCronTick(
	ctx context.Context, key, tool, target, status, jobID, summary string, durationMS int64, now time.Time,
) (CronStateRecord, bool, error) {
	return s.applyCronTick(ctx, key, tool, target, status, jobID, summary, durationMS, now)
}

// GetCronStatus returns all cron_state entries and daily rollup/tick buckets for "24h", "7d", or "30d".
func (s *JobStore) GetCronStatus(ctx context.Context, period string) (*CronSummary, error) {
	return s.buildCronSummary(ctx, period)
}

// SaveSnapshot stores or updates a named snapshot in the snapshots table.
func (s *JobStore) SaveSnapshot(ctx context.Context, snap *SnapshotRecord) error {
	if snap == nil || strings.TrimSpace(snap.Name) == "" {
		return errors.New("snapshot record and name must not be empty")
	}
	if snap.CreatedAt == 0 {
		snap.CreatedAt = time.Now().UTC().Unix()
	}
	const q = `INSERT INTO snapshots (name, job_id, target, payload_json, created_at) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(name) DO UPDATE SET job_id=excluded.job_id, target=excluded.target, payload_json=excluded.payload_json, created_at=excluded.created_at;`
	if _, err := s.rwDB.ExecContext(ctx, q, snap.Name, snap.JobID, snap.Target, snap.PayloadJSON, snap.CreatedAt); err != nil {
		return fmt.Errorf("save snapshot %q: %w", snap.Name, err)
	}
	return nil
}

// GetSnapshot retrieves a named snapshot via the read-only pool.
func (s *JobStore) GetSnapshot(ctx context.Context, name string) (*SnapshotRecord, error) {
	const q = `SELECT name, job_id, target, payload_json, created_at FROM snapshots WHERE name = ?;`
	var snap SnapshotRecord
	if err := s.roDB.QueryRowContext(ctx, q, name).Scan(&snap.Name, &snap.JobID, &snap.Target, &snap.PayloadJSON, &snap.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("snapshot %q (%w): %w", name, ErrNotFound, err)
		}
		return nil, fmt.Errorf("get snapshot %q: %w", name, err)
	}
	return &snap, nil
}

// ListSnapshots returns all stored snapshots ordered newest first.
func (s *JobStore) ListSnapshots(ctx context.Context) ([]SnapshotRecord, error) {
	const q = `SELECT name, job_id, target, payload_json, created_at FROM snapshots ORDER BY created_at DESC, rowid DESC;`
	rows, err := s.roDB.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list snapshots: %w", err)
	}
	defer rows.Close()

	var snaps []SnapshotRecord
	for rows.Next() {
		var snap SnapshotRecord
		if err := rows.Scan(&snap.Name, &snap.JobID, &snap.Target, &snap.PayloadJSON, &snap.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan snapshot row: %w", err)
		}
		snaps = append(snaps, snap)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate snapshot rows: %w", err)
	}
	return snaps, nil
}

// Stats returns row counts, storage size, and SQLite configuration metadata.
func (s *JobStore) Stats(ctx context.Context) (StoreStats, error) {
	stats := StoreStats{DBPath: s.dbPath, MaxStoreBytes: s.maxStoreBytes}
	const countsSQL = `SELECT (SELECT COUNT(*) FROM jobs), (SELECT COUNT(*) FROM jobs WHERE is_incident = 1), (SELECT COUNT(*) FROM cron_state), (SELECT COUNT(*) FROM cron_daily_rollups), (SELECT COUNT(*) FROM snapshots), (SELECT COUNT(*) FROM saved_destinations);`
	if err := s.roDB.QueryRowContext(ctx, countsSQL).Scan(
		&stats.JobCount, &stats.IncidentCount, &stats.CronStateCount, &stats.DailyRollupRows, &stats.SnapshotCount, &stats.DestinationCount,
	); err != nil {
		return StoreStats{}, fmt.Errorf("query store counts: %w", err)
	}
	if err := s.readStorePragmas(ctx, &stats); err != nil {
		return StoreStats{}, err
	}
	if s.filePath == "" {
		stats.DBSizeBytes = stats.PageSize * stats.PageCount
		return stats, nil
	}
	sizeBytes, err := s.currentDBSizeBytes(ctx)
	if err != nil {
		return StoreStats{}, err
	}
	stats.DBSizeBytes = sizeBytes
	return stats, nil
}

func scanJob(scanner rowScanner) (*JobRecord, error) {
	var rec JobRecord
	var isIncidentInt, downAgedInt int
	if err := scanner.Scan(
		&rec.JobID, &rec.ToolName, &rec.Target, &rec.Source, &rec.Status, &rec.Summary,
		&rec.PayloadJSON, &rec.ASCIIDefault, &rec.DurationMS, &rec.CreatedAt, &rec.ExpiresAt,
		&isIncidentInt, &downAgedInt,
	); err != nil {
		return nil, fmt.Errorf("scan job: %w", err)
	}
	rec.IsIncident, rec.DownAged = isIncidentInt != 0, downAgedInt != 0
	return &rec, nil
}

func generateJobID(createdAt int64) (string, error) {
	var raw [jobIDRandByteSize]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate job_id entropy: %w", err)
	}
	return fmt.Sprintf("job_%d_%s", createdAt, hex.EncodeToString(raw[:])), nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
