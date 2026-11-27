package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// ReaperStats summarizes the actions taken during one RunReaperOnce pass.
type ReaperStats struct {
	DownAgedRows   int64 `json:"down_aged_rows"`
	ExpiredDeleted int64 `json:"expired_deleted"`
	EvictedForSize int64 `json:"evicted_for_size"`
	DBSizeBefore   int64 `json:"db_size_before"`
	DBSizeAfter    int64 `json:"db_size_after"`
	VacuumRan      bool  `json:"vacuum_ran"`
}

const (
	// DefaultRetention is the default job retention TTL (30 days).
	DefaultRetention = 30 * 24 * time.Hour
	// HealthyTickDetailWindow keeps raw 5-minute OK cron rows for 7 days before down-aging.
	HealthyTickDetailWindow = 7 * 24 * time.Hour
	// DefaultMaxStoreMB is the default database size ceiling in MiB.
	DefaultMaxStoreMB = 256
	// DefaultReaperInterval is the default interval between background reaper runs.
	DefaultReaperInterval = time.Hour

	evictionBatchSize     = 50
	maxEvictionIterations = 10000
	evictionTargetPercent = 90

	upsertHealthyRollupsSQL = `INSERT INTO cron_daily_rollups (day_utc, job_key, ok_count, warn_count, fail_count, avg_duration_ms, updated_at)
SELECT strftime('%Y-%m-%d', j.created_at, 'unixepoch') AS day_utc,
	COALESCE((SELECT cs.job_key FROM cron_state cs WHERE cs.tool_name = j.tool_name AND cs.target = j.target LIMIT 1), j.tool_name || ':' || j.target) AS job_key,
	COUNT(*) AS ok_count, 0 AS warn_count, 0 AS fail_count, COALESCE(AVG(CAST(j.duration_ms AS REAL)), 0.0) AS avg_duration_ms, ? AS updated_at
FROM jobs j WHERE UPPER(j.status) = 'OK' AND j.is_incident = 0 AND j.source = 'cron' AND j.down_aged = 0 AND j.created_at <= ? GROUP BY day_utc, job_key
ON CONFLICT(day_utc, job_key) DO UPDATE SET
	avg_duration_ms = CASE WHEN (cron_daily_rollups.ok_count + cron_daily_rollups.warn_count + cron_daily_rollups.fail_count + excluded.ok_count) > 0
		THEN ((cron_daily_rollups.avg_duration_ms * (cron_daily_rollups.ok_count + cron_daily_rollups.warn_count + cron_daily_rollups.fail_count)) + (excluded.avg_duration_ms * excluded.ok_count)) / (cron_daily_rollups.ok_count + cron_daily_rollups.warn_count + cron_daily_rollups.fail_count + excluded.ok_count)
		ELSE 0.0 END,
	ok_count = cron_daily_rollups.ok_count + excluded.ok_count, updated_at = excluded.updated_at;`
	deleteDownAgedHealthySQL  = `DELETE FROM jobs WHERE UPPER(status) = 'OK' AND is_incident = 0 AND source = 'cron' AND down_aged = 0 AND created_at <= ?;`
	evictOldestNonIncidentSQL = `DELETE FROM jobs WHERE job_id IN (SELECT job_id FROM jobs WHERE is_incident = 0 ORDER BY created_at ASC, rowid ASC LIMIT ?);`
	queryRollupBucketsSQL     = `SELECT day_utc, job_key, ok_count, warn_count, fail_count, avg_duration_ms, updated_at FROM cron_daily_rollups WHERE day_utc >= ? ORDER BY day_utc ASC, job_key ASC;`
	queryRecentTickBucketsSQL = `SELECT strftime('%Y-%m-%d', j.created_at, 'unixepoch') AS day_utc,
	COALESCE((SELECT cs.job_key FROM cron_state cs WHERE cs.tool_name = j.tool_name AND cs.target = j.target LIMIT 1), j.tool_name || ':' || j.target) AS job_key,
	SUM(CASE WHEN UPPER(j.status) = 'OK' THEN 1 ELSE 0 END), SUM(CASE WHEN UPPER(j.status) = 'WARN' THEN 1 ELSE 0 END),
	SUM(CASE WHEN UPPER(j.status) NOT IN ('OK', 'WARN') THEN 1 ELSE 0 END), COALESCE(AVG(CAST(j.duration_ms AS REAL)), 0.0), MAX(j.created_at)
FROM jobs j WHERE j.source = 'cron' AND j.created_at >= ? AND j.down_aged = 0 GROUP BY day_utc, job_key ORDER BY day_utc ASC, job_key ASC;`
)

// DownAgeHealthyTicks compacts healthy non-incident cron rows older than 7 days
// into cron_daily_rollups and removes the raw 5m detail rows in one transaction.
func (s *JobStore) DownAgeHealthyTicks(ctx context.Context, now time.Time) (int64, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowUTC := now.UTC()
	cutoff := nowUTC.Add(-HealthyTickDetailWindow).Unix()

	tx, err := s.rwDB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin down-age tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, upsertHealthyRollupsSQL, nowUTC.Unix(), cutoff); err != nil {
		return 0, fmt.Errorf("upsert healthy cron rollups: %w", err)
	}
	res, err := tx.ExecContext(ctx, deleteDownAgedHealthySQL, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete compacted healthy ticks: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count compacted healthy ticks: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit down-age tx: %w", err)
	}
	return affected, nil
}

// RunReaperOnce executes down-aging, TTL expiry, max-store-mb eviction, and incremental vacuum.
func (s *JobStore) RunReaperOnce(ctx context.Context, now time.Time) (ReaperStats, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var stats ReaperStats
	before, err := s.currentDBSizeBytes(ctx)
	if err != nil {
		return ReaperStats{}, err
	}
	stats.DBSizeBefore = before

	if stats.DownAgedRows, err = s.DownAgeHealthyTicks(ctx, now); err != nil {
		return stats, err
	}
	res, err := s.rwDB.ExecContext(ctx, "DELETE FROM jobs WHERE expires_at <= ?;", now.UTC().Unix())
	if err != nil {
		return stats, fmt.Errorf("delete expired jobs: %w", err)
	}
	if stats.ExpiredDeleted, err = res.RowsAffected(); err != nil {
		return stats, fmt.Errorf("count expired jobs: %w", err)
	}
	if stats.EvictedForSize, err = s.enforceMaxStoreSize(ctx); err != nil {
		return stats, err
	}
	if err := s.runIncrementalVacuum(ctx); err != nil {
		return stats, err
	}
	stats.VacuumRan = true
	if err := s.checkpointTruncate(ctx); err != nil {
		return stats, err
	}
	if stats.DBSizeAfter, err = s.currentDBSizeBytes(ctx); err != nil {
		return stats, err
	}
	return stats, nil
}

// StartReaper spawns a background goroutine that invokes RunReaperOnce every interval.
// It exits cleanly when ctx is canceled or Close is called.
func (s *JobStore) StartReaper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultReaperInterval
	}
	s.reaperMu.Lock()
	if s.closed {
		s.reaperMu.Unlock()
		return
	}
	s.wg.Add(1)
	s.reaperMu.Unlock()

	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.baseCtx.Done():
				return
			case <-ticker.C:
				tickCtx, cancel := context.WithCancel(ctx)
				stopWatch := make(chan struct{})
				watchDone := make(chan struct{})
				go func() {
					defer close(watchDone)
					select {
					case <-s.baseCtx.Done():
						cancel()
					case <-stopWatch:
					}
				}()
				_, _ = s.RunReaperOnce(tickCtx, time.Now().UTC())
				close(stopWatch)
				<-watchDone
				cancel()
			}
		}
	}()
}

func (s *JobStore) applyCronTick(
	ctx context.Context, key, tool, target, status, jobID, summary string, durationMS int64, now time.Time,
) (CronStateRecord, bool, error) {
	if strings.TrimSpace(key) == "" {
		return CronStateRecord{}, false, errors.New("cron job key must not be empty")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	normStatus := strings.ToUpper(strings.TrimSpace(status))
	if normStatus == "" {
		normStatus = "FAIL"
	}
	tx, err := s.rwDB.BeginTx(ctx, nil)
	if err != nil {
		return CronStateRecord{}, false, fmt.Errorf("begin cron tick tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	prev, exists, err := readCronStateTx(ctx, tx, key)
	if err != nil {
		return CronStateRecord{}, false, err
	}
	next, flipped := nextCronHysteresisState(&prev, exists, key, tool, target, normStatus, jobID, summary, now.UTC().Unix())
	if err := upsertCronStateTx(ctx, tx, &next); err != nil {
		return CronStateRecord{}, false, err
	}
	if jobID != "" && durationMS > 0 {
		if _, err := tx.ExecContext(ctx, "UPDATE jobs SET duration_ms = ? WHERE job_id = ? AND duration_ms = 0;", durationMS, jobID); err != nil {
			return CronStateRecord{}, false, fmt.Errorf("backfill job duration: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return CronStateRecord{}, false, fmt.Errorf("commit cron tick tx: %w", err)
	}
	return next, flipped, nil
}

func (s *JobStore) readStorePragmas(ctx context.Context, stats *StoreStats) error {
	for _, p := range []struct {
		stmt string
		dest *int64
	}{
		{"PRAGMA page_size;", &stats.PageSize},
		{"PRAGMA page_count;", &stats.PageCount},
		{"PRAGMA freelist_count;", &stats.FreelistCount},
		{"PRAGMA auto_vacuum;", &stats.AutoVacuum},
	} {
		if err := s.roDB.QueryRowContext(ctx, p.stmt).Scan(p.dest); err != nil {
			return fmt.Errorf("query %s: %w", p.stmt, err)
		}
	}
	if err := s.roDB.QueryRowContext(ctx, "PRAGMA journal_mode;").Scan(&stats.JournalMode); err != nil {
		return fmt.Errorf("query PRAGMA journal_mode: %w", err)
	}
	return nil
}

func scanCronState(scanner rowScanner) (CronStateRecord, error) {
	var rec CronStateRecord
	var activeInt int
	if err := scanner.Scan(
		&rec.JobKey, &rec.ToolName, &rec.Target, &rec.ConsecutiveNonOK, &activeInt,
		&rec.LastStatus, &rec.LastTickAt, &rec.LastAlertFlipAt, &rec.LastJobID, &rec.LastSummary,
	); err != nil {
		return CronStateRecord{}, fmt.Errorf("scan cron state: %w", err)
	}
	rec.ActiveAlert = activeInt != 0
	return rec, nil
}

func readCronStateTx(ctx context.Context, tx *sql.Tx, key string) (CronStateRecord, bool, error) {
	const q = `SELECT job_key, tool_name, target, consecutive_non_ok, active_alert, last_status, last_tick_at, last_alert_flip_at, last_job_id, last_summary FROM cron_state WHERE job_key = ?;`
	rec, err := scanCronState(tx.QueryRowContext(ctx, q, key))
	if errors.Is(err, sql.ErrNoRows) {
		return CronStateRecord{}, false, nil
	}
	if err != nil {
		return CronStateRecord{}, false, fmt.Errorf("read cron state %q: %w", key, err)
	}
	return rec, true, nil
}

func nextCronHysteresisState(
	prev *CronStateRecord, exists bool, key, tool, target, status, jobID, summary string, nowUnix int64,
) (CronStateRecord, bool) {
	next := CronStateRecord{
		JobKey: key, ToolName: tool, Target: target, LastStatus: status,
		LastTickAt: nowUnix, LastAlertFlipAt: prev.LastAlertFlipAt, LastJobID: jobID, LastSummary: summary,
	}
	if status == "OK" {
		flipped := exists && prev.ActiveAlert
		if flipped {
			next.LastAlertFlipAt = nowUnix
		}
		return next, flipped
	}
	next.ConsecutiveNonOK = prev.ConsecutiveNonOK + 1
	next.ActiveAlert = prev.ActiveAlert || next.ConsecutiveNonOK >= 2
	flipped := next.ActiveAlert != prev.ActiveAlert
	if flipped {
		next.LastAlertFlipAt = nowUnix
	}
	return next, flipped
}

func upsertCronStateTx(ctx context.Context, tx *sql.Tx, rec *CronStateRecord) error {
	const q = `INSERT INTO cron_state (job_key, tool_name, target, consecutive_non_ok, active_alert, last_status, last_tick_at, last_alert_flip_at, last_job_id, last_summary)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(job_key) DO UPDATE SET
	tool_name=excluded.tool_name, target=excluded.target, consecutive_non_ok=excluded.consecutive_non_ok,
	active_alert=excluded.active_alert, last_status=excluded.last_status, last_tick_at=excluded.last_tick_at,
	last_alert_flip_at=excluded.last_alert_flip_at, last_job_id=excluded.last_job_id, last_summary=excluded.last_summary;`
	if _, err := tx.ExecContext(
		ctx, q, rec.JobKey, rec.ToolName, rec.Target, rec.ConsecutiveNonOK, boolToInt(rec.ActiveAlert),
		rec.LastStatus, rec.LastTickAt, rec.LastAlertFlipAt, rec.LastJobID, rec.LastSummary,
	); err != nil {
		return fmt.Errorf("upsert cron state %q: %w", rec.JobKey, err)
	}
	return nil
}

func (s *JobStore) queryCronStates(ctx context.Context) ([]CronStateRecord, error) {
	const q = `SELECT job_key, tool_name, target, consecutive_non_ok, active_alert, last_status, last_tick_at, last_alert_flip_at, last_job_id, last_summary FROM cron_state ORDER BY job_key ASC;`
	rows, err := s.roDB.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query cron states: %w", err)
	}
	defer rows.Close()

	var states []CronStateRecord
	for rows.Next() {
		rec, scanErr := scanCronState(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		states = append(states, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cron states: %w", err)
	}
	return states, nil
}

func (s *JobStore) buildCronSummary(ctx context.Context, period string) (*CronSummary, error) {
	window, normPeriod, err := parseCronPeriod(period)
	if err != nil {
		return nil, err
	}
	since := time.Now().UTC().Add(-window)
	sinceUnix := since.Unix()

	states, err := s.queryCronStates(ctx)
	if err != nil {
		return nil, err
	}
	merged := make(map[string]CronDailyStat)
	if err := s.scanDailyBucketQuery(ctx, queryRollupBucketsSQL, since.Format("2006-01-02"), merged); err != nil {
		return nil, fmt.Errorf("query cron daily rollups: %w", err)
	}
	if err := s.scanDailyBucketQuery(ctx, queryRecentTickBucketsSQL, sinceUnix, merged); err != nil {
		return nil, fmt.Errorf("query recent cron ticks: %w", err)
	}
	stats := make([]CronDailyStat, 0, len(merged))
	for _, bucket := range merged {
		stats = append(stats, bucket)
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].DayUTC != stats[j].DayUTC {
			return stats[i].DayUTC < stats[j].DayUTC
		}
		return stats[i].JobKey < stats[j].JobKey
	})
	return &CronSummary{Period: normPeriod, Since: sinceUnix, States: states, DailyStats: stats}, nil
}

func (s *JobStore) scanDailyBucketQuery(ctx context.Context, query string, arg any, dst map[string]CronDailyStat) error {
	rows, err := s.roDB.QueryContext(ctx, query, arg)
	if err != nil {
		return fmt.Errorf("execute bucket query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var item CronDailyStat
		if err := rows.Scan(
			&item.DayUTC, &item.JobKey, &item.OKCount, &item.WarnCount,
			&item.FailCount, &item.AvgDurationMS, &item.UpdatedAt,
		); err != nil {
			return fmt.Errorf("scan daily bucket: %w", err)
		}
		mergeDailyStat(dst, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate daily buckets: %w", err)
	}
	return nil
}

func mergeDailyStat(dst map[string]CronDailyStat, add CronDailyStat) {
	mapKey := add.DayUTC + "\x00" + add.JobKey
	cur, exists := dst[mapKey]
	if !exists {
		dst[mapKey] = add
		return
	}
	curCount := cur.OKCount + cur.WarnCount + cur.FailCount
	addCount := add.OKCount + add.WarnCount + add.FailCount
	if total := curCount + addCount; total > 0 {
		cur.AvgDurationMS = (cur.AvgDurationMS*float64(curCount) + add.AvgDurationMS*float64(addCount)) / float64(total)
	}
	cur.OKCount += add.OKCount
	cur.WarnCount += add.WarnCount
	cur.FailCount += add.FailCount
	cur.UpdatedAt = max(cur.UpdatedAt, add.UpdatedAt)
	dst[mapKey] = cur
}

func parseCronPeriod(period string) (time.Duration, string, error) {
	switch strings.ToLower(strings.TrimSpace(period)) {
	case "", "24h":
		return 24 * time.Hour, "24h", nil
	case "7d":
		return 7 * 24 * time.Hour, "7d", nil
	case "30d":
		return 30 * 24 * time.Hour, "30d", nil
	default:
		return 0, "", fmt.Errorf("%w: %q (expected 24h, 7d, or 30d)", ErrInvalidPeriod, period)
	}
}

func (s *JobStore) enforceMaxStoreSize(ctx context.Context) (int64, error) {
	if s.maxStoreBytes <= 0 {
		return 0, nil
	}
	if err := s.checkpointTruncate(ctx); err != nil {
		return 0, err
	}
	curSize, err := s.currentDBSizeBytes(ctx)
	if err != nil || curSize <= s.maxStoreBytes {
		return 0, err
	}
	targetBytes := (s.maxStoreBytes * evictionTargetPercent) / 100
	var totalEvicted int64
	freelistDrained := false

	for range maxEvictionIterations {
		if !freelistDrained {
			if curSize <= s.maxStoreBytes {
				break
			}
			var freePages int64
			if err := s.rwDB.QueryRowContext(ctx, "PRAGMA freelist_count;").Scan(&freePages); err != nil {
				return totalEvicted, fmt.Errorf("query freelist_count: %w", err)
			}
			if freePages == 0 {
				freelistDrained = true
				continue
			}
		} else {
			if curSize <= targetBytes {
				break
			}
			res, execErr := s.rwDB.ExecContext(ctx, evictOldestNonIncidentSQL, evictionBatchSize)
			if execErr != nil {
				return totalEvicted, fmt.Errorf("evict oldest non-incident jobs: %w", execErr)
			}
			affected, affErr := res.RowsAffected()
			if affErr != nil {
				return totalEvicted, fmt.Errorf("count evicted jobs: %w", affErr)
			}
			if affected == 0 {
				break
			}
			totalEvicted += affected
		}
		if curSize, err = s.vacuumAndMeasure(ctx); err != nil {
			return totalEvicted, err
		}
	}
	return totalEvicted, nil
}

func (s *JobStore) vacuumAndMeasure(ctx context.Context) (int64, error) {
	if err := s.runIncrementalVacuum(ctx); err != nil {
		return 0, err
	}
	if err := s.checkpointTruncate(ctx); err != nil {
		return 0, err
	}
	return s.currentDBSizeBytes(ctx)
}

func (s *JobStore) runIncrementalVacuum(ctx context.Context) error {
	if _, err := s.rwDB.ExecContext(ctx, "PRAGMA incremental_vacuum(200);"); err != nil {
		return fmt.Errorf("run incremental_vacuum(200): %w", err)
	}
	return nil
}

func (s *JobStore) checkpointTruncate(ctx context.Context) error {
	if s.filePath == "" {
		return nil
	}
	var busy, logFrames, checkpointed int
	if err := s.rwDB.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE);").Scan(&busy, &logFrames, &checkpointed); err != nil {
		return fmt.Errorf("wal checkpoint truncate: %w", err)
	}
	return nil
}

func (s *JobStore) currentDBSizeBytes(ctx context.Context) (int64, error) {
	if s.filePath == "" {
		var pageSize, pageCount int64
		if err := s.rwDB.QueryRowContext(ctx, "PRAGMA page_size;").Scan(&pageSize); err != nil {
			return 0, fmt.Errorf("query memory page_size: %w", err)
		}
		if err := s.rwDB.QueryRowContext(ctx, "PRAGMA page_count;").Scan(&pageCount); err != nil {
			return 0, fmt.Errorf("query memory page_count: %w", err)
		}
		return pageSize * pageCount, nil
	}
	info, err := os.Stat(s.filePath)
	if err != nil {
		return 0, fmt.Errorf("stat db file %q: %w", s.filePath, err)
	}
	total := info.Size()
	if walInfo, walErr := os.Stat(s.filePath + "-wal"); walErr == nil {
		total += walInfo.Size()
	} else if !errors.Is(walErr, os.ErrNotExist) {
		return 0, fmt.Errorf("stat wal file: %w", walErr)
	}
	return total, nil
}
