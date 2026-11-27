package webui

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/dispatch"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
)

// CronTimeseriesBucket represents an aggregated latency and health bucket for /api/cron timeseries.
type CronTimeseriesBucket struct {
	TS         int64   `json:"ts"`
	Label      string  `json:"label"`
	AvgMS      float64 `json:"avg_ms"`
	MaxMS      float64 `json:"max_ms"`
	MinMS      float64 `json:"min_ms"`
	OKCount    int64   `json:"ok_count"`
	WarnCount  int64   `json:"warn_count"`
	FailCount  int64   `json:"fail_count"`
	TotalCount int64   `json:"total_count"`
	UptimePct  float64 `json:"uptime_pct"`
	Status     string  `json:"status"`
}

type cronResponse struct {
	Locked       bool                       `json:"locked,omitempty"`
	Summary      workspaceSummary           `json:"summary"`
	Warmup       bool                       `json:"warmup"`
	Strip        []stripDay                 `json:"strip"`
	Watchlist    []watchlistRow             `json:"watchlist"`
	Jobs         []jobSummaryRow            `json:"jobs"`
	Timeseries   []CronTimeseriesBucket     `json:"timeseries"`
	Range        string                     `json:"range"`
	LANInventory *dispatch.LANInventoryView `json:"lan_inventory,omitempty"`
}

type tsBucketAgg struct {
	ts       int64
	ok       int64
	warn     int64
	fail     int64
	durSum   float64
	minMS    float64
	maxMS    float64
	hasMin   bool
	weighted bool
}

const timeseriesJobsLimit = 10000

func parseTimeseriesRange(raw string) (time.Duration, time.Duration, string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "24h":
		return 24 * time.Hour, time.Hour, "24h", nil
	case "7d":
		return 7 * 24 * time.Hour, 6 * time.Hour, "7d", nil
	case "30d":
		return 30 * 24 * time.Hour, 24 * time.Hour, "30d", nil
	default:
		return 0, 0, "", fmt.Errorf("%w: %q (expected 24h, 7d, or 30d)", store.ErrInvalidPeriod, raw)
	}
}

func buildCronTimeseries(
	ctx context.Context, st *store.JobStore, cronStatus *store.CronSummary, rawRange string, now time.Time,
) ([]CronTimeseriesBucket, string, int64, error) {
	window, step, normRange, err := parseTimeseriesRange(rawRange)
	if err != nil {
		return nil, "", 0, err
	}
	if st == nil {
		return []CronTimeseriesBucket{}, normRange, 0, nil
	}
	nowUTC := now.UTC()
	since := nowUTC.Add(-window)
	jobs, err := st.ListJobs(ctx, store.JobFilter{
		Since: since.Unix(), Until: nowUTC.Unix(), Limit: timeseriesJobsLimit,
	})
	if err != nil {
		return nil, "", 0, fmt.Errorf("query timeseries jobs: %w", err)
	}
	byTS, coveredDays := aggregateJobsToBuckets(jobs, int64(step.Seconds()))
	if normRange == "24h" && len(jobs) >= 2 && len(byTS) < 4 {
		buckets, sampleCount := buildPerRunBuckets(jobs)
		return buckets, normRange, sampleCount, nil
	}
	if cronStatus != nil && (normRange != "24h" || len(byTS) == 0) {
		mergeDailyStatsIntoBuckets(byTS, coveredDays, cronStatus.DailyStats, since.Format("2006-01-02"), nowUTC.Format("2006-01-02"))
	}
	return finalizeTimeseriesBuckets(byTS, normRange)
}

func buildPerRunBuckets(jobs []store.JobRecord) ([]CronTimeseriesBucket, int64) {
	sorted := make([]store.JobRecord, len(jobs))
	copy(sorted, jobs)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].CreatedAt != sorted[j].CreatedAt {
			return sorted[i].CreatedAt < sorted[j].CreatedAt
		}
		return sorted[i].JobID < sorted[j].JobID
	})
	sampleCount := int64(len(sorted))
	if len(sorted) > 120 {
		sorted = sorted[len(sorted)-120:]
	}
	out := make([]CronTimeseriesBucket, 0, len(sorted))
	for i := range sorted {
		j := &sorted[i]
		st := "FAIL"
		var okCnt, warnCnt, failCnt int64
		var uptimePct float64
		switch strings.ToUpper(strings.TrimSpace(j.Status)) {
		case "OK":
			st = "OK"
			okCnt = 1
			uptimePct = 100
		case "WARN":
			st = "WARN"
			warnCnt = 1
		default:
			failCnt = 1
		}
		dur := float64(j.DurationMS)
		out = append(out, CronTimeseriesBucket{
			TS:         j.CreatedAt,
			Label:      time.Unix(j.CreatedAt, 0).UTC().Format("15:04:05"),
			AvgMS:      dur,
			MaxMS:      dur,
			MinMS:      dur,
			OKCount:    okCnt,
			WarnCount:  warnCnt,
			FailCount:  failCnt,
			TotalCount: 1,
			UptimePct:  uptimePct,
			Status:     st,
		})
	}
	return out, sampleCount
}

func aggregateJobsToBuckets(jobs []store.JobRecord, stepSec int64) (map[int64]*tsBucketAgg, map[string]bool) {
	byTS := make(map[int64]*tsBucketAgg)
	coveredDays := make(map[string]bool)
	for i := range jobs {
		j := &jobs[i]
		ts := (j.CreatedAt / stepSec) * stepSec
		coveredDays[time.Unix(j.CreatedAt, 0).UTC().Format("2006-01-02")] = true
		b := getOrCreateTSBucket(byTS, ts)
		switch strings.ToUpper(strings.TrimSpace(j.Status)) {
		case "OK":
			b.ok++
		case "WARN":
			b.warn++
		default:
			b.fail++
		}
		dur := float64(j.DurationMS)
		b.durSum += dur
		if !b.hasMin || dur < b.minMS {
			b.minMS = dur
			b.hasMin = true
		}
		if dur > b.maxMS {
			b.maxMS = dur
		}
	}
	return byTS, coveredDays
}

func mergeDailyStatsIntoBuckets(
	byTS map[int64]*tsBucketAgg, coveredDays map[string]bool, daily []store.CronDailyStat, sinceDay, nowDay string,
) {
	for i := range daily {
		d := &daily[i]
		if coveredDays[d.DayUTC] || d.DayUTC < sinceDay || d.DayUTC > nowDay {
			continue
		}
		dayTime, err := time.Parse("2006-01-02", d.DayUTC)
		if err != nil {
			continue
		}
		ticks := d.OKCount + d.WarnCount + d.FailCount
		if ticks <= 0 {
			continue
		}
		b := getOrCreateTSBucket(byTS, dayTime.UTC().Unix())
		b.weighted = true
		b.ok += d.OKCount
		b.warn += d.WarnCount
		b.fail += d.FailCount
		b.durSum += d.AvgDurationMS * float64(ticks)
		if !b.hasMin || d.AvgDurationMS < b.minMS {
			b.minMS = d.AvgDurationMS
			b.hasMin = true
		}
		if d.AvgDurationMS > b.maxMS {
			b.maxMS = d.AvgDurationMS
		}
	}
}

func getOrCreateTSBucket(byTS map[int64]*tsBucketAgg, ts int64) *tsBucketAgg {
	b := byTS[ts]
	if b == nil {
		b = &tsBucketAgg{ts: ts}
		byTS[ts] = b
	}
	return b
}

func finalizeTimeseriesBuckets(byTS map[int64]*tsBucketAgg, normRange string) ([]CronTimeseriesBucket, string, int64, error) {
	keys := make([]int64, 0, len(byTS))
	for ts := range byTS {
		keys = append(keys, ts)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	out := make([]CronTimeseriesBucket, 0, len(keys))
	var sampleCount int64
	for _, ts := range keys {
		b := byTS[ts]
		total := b.ok + b.warn + b.fail
		sampleCount += total
		var avgMS, uptimePct float64
		if total > 0 {
			avgMS = roundTo(b.durSum/float64(total), 2)
			uptimePct = roundTo((float64(b.ok)/float64(total))*100, 1)
		}
		status := "OK"
		if b.fail > 0 {
			status = "FAIL"
		} else if b.warn > 0 {
			status = "WARN"
		}
		out = append(out, CronTimeseriesBucket{
			TS:         ts,
			Label:      formatBucketLabel(ts, normRange),
			AvgMS:      avgMS,
			MaxMS:      roundTo(b.maxMS, 2),
			MinMS:      roundTo(b.minMS, 2),
			OKCount:    b.ok,
			WarnCount:  b.warn,
			FailCount:  b.fail,
			TotalCount: total,
			UptimePct:  uptimePct,
			Status:     status,
		})
	}
	return out, normRange, sampleCount, nil
}

func formatBucketLabel(ts int64, normRange string) string {
	t := time.Unix(ts, 0).UTC()
	switch normRange {
	case "24h":
		return t.Format("15:04")
	case "7d":
		return t.Format("01-02 15:04")
	default:
		return t.Format("2006-01-02")
	}
}

func roundTo(val float64, decimals int) float64 {
	pow := math.Pow10(decimals)
	return math.Round(val*pow) / pow
}
