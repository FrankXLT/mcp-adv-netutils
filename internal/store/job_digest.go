package store

import (
	"context"
	"fmt"
	"math"
)

// ToolDigestCount summarizes job outcomes and average latency for a single tool.
type ToolDigestCount struct {
	ToolName      string  `json:"tool_name"`
	Total         int     `json:"total"`
	OKCount       int     `json:"ok_count"`
	WarnCount     int     `json:"warn_count"`
	FailCount     int     `json:"fail_count"`
	AvgDurationMS float64 `json:"avg_duration_ms"`
}

// TargetProblemCount aggregates non-OK outcomes for a target within a window.
type TargetProblemCount struct {
	Target     string `json:"target"`
	WarnCount  int    `json:"warn_count"`
	FailCount  int    `json:"fail_count"`
	TotalNonOK int    `json:"total_non_ok"`
	LastSeenAt int64  `json:"last_seen_at"`
}

// JobWindowSummary holds aggregate job metrics, problem targets, and per-tool breakdowns.
type JobWindowSummary struct {
	TotalMatching     int                  `json:"total_matching"`
	OKCount           int                  `json:"ok_count"`
	WarnCount         int                  `json:"warn_count"`
	FailCount         int                  `json:"fail_count"`
	IncidentCount     int                  `json:"incident_count"`
	PassRatePct       float64              `json:"pass_rate_pct"`
	AvgDurationMS     float64              `json:"avg_duration_ms"`
	MinDurationMS     int64                `json:"min_duration_ms"`
	MaxDurationMS     int64                `json:"max_duration_ms"`
	EarliestCreatedAt int64                `json:"earliest_created_at,omitempty"`
	LatestCreatedAt   int64                `json:"latest_created_at,omitempty"`
	TopProblemTargets []TargetProblemCount `json:"top_problem_targets,omitempty"`
	ToolBreakdown     []ToolDigestCount    `json:"tool_breakdown,omitempty"`
}

const (
	toolBreakdownLimit     = 15
	topProblemTargetsLimit = 10

	jobIsFailSQL  = `UPPER(TRIM(status)) IN ('FAIL', 'ERROR', 'ERR', 'CRITICAL', 'DOWN')`
	jobIsWarnSQL  = `UPPER(TRIM(status)) IN ('WARN', 'WARNING', 'DEGRADED')`
	jobIsNonOKSQL = `UPPER(TRIM(status)) IN ('FAIL', 'ERROR', 'ERR', 'CRITICAL', 'DOWN', 'WARN', 'WARNING', 'DEGRADED')`

	jobStatusFilterSQL = `(TRIM(?) = '' OR CASE UPPER(TRIM(?)) WHEN 'FAIL' THEN (` + jobIsFailSQL + `) WHEN 'WARN' THEN (` + jobIsWarnSQL + `) WHEN 'OK' THEN NOT (` + jobIsFailSQL + ` OR ` + jobIsWarnSQL + `) ELSE UPPER(TRIM(status)) = UPPER(TRIM(?)) END)`

	jobFilterWhereClause = `(? = '' OR tool_name = ?) AND (? = '' OR target = ?) AND (? = '' OR INSTR(LOWER(target), LOWER(?)) > 0) AND (? = '' OR source = ?) AND ` + jobStatusFilterSQL + ` AND (? = 0 OR created_at >= ?) AND (? = 0 OR created_at <= ?) AND (? = 0 OR is_incident = 1)`

	summarizeJobsSQL = `SELECT
	COUNT(*),
	COALESCE(SUM(CASE WHEN NOT (` + jobIsNonOKSQL + `) THEN 1 ELSE 0 END), 0),
	COALESCE(SUM(CASE WHEN ` + jobIsWarnSQL + ` THEN 1 ELSE 0 END), 0),
	COALESCE(SUM(CASE WHEN ` + jobIsFailSQL + ` THEN 1 ELSE 0 END), 0),
	COALESCE(SUM(CASE WHEN is_incident != 0 THEN 1 ELSE 0 END), 0),
	COALESCE(AVG(CAST(duration_ms AS REAL)), 0.0),
	COALESCE(MIN(duration_ms), 0),
	COALESCE(MAX(duration_ms), 0),
	COALESCE(MIN(created_at), 0),
	COALESCE(MAX(created_at), 0)
FROM jobs WHERE ` + jobFilterWhereClause + `;`

	toolBreakdownSQL = `SELECT
	tool_name,
	COUNT(*) AS total,
	COALESCE(SUM(CASE WHEN NOT (` + jobIsNonOKSQL + `) THEN 1 ELSE 0 END), 0) AS ok_count,
	COALESCE(SUM(CASE WHEN ` + jobIsWarnSQL + ` THEN 1 ELSE 0 END), 0) AS warn_count,
	COALESCE(SUM(CASE WHEN ` + jobIsFailSQL + ` THEN 1 ELSE 0 END), 0) AS fail_count,
	COALESCE(AVG(CAST(duration_ms AS REAL)), 0.0) AS avg_duration_ms
FROM jobs
WHERE ` + jobFilterWhereClause + `
GROUP BY tool_name
ORDER BY (fail_count + warn_count) DESC, total DESC, tool_name ASC
LIMIT ?;`

	topProblemTargetsSQL = `SELECT
	target,
	COALESCE(SUM(CASE WHEN ` + jobIsWarnSQL + ` THEN 1 ELSE 0 END), 0) AS warn_count,
	COALESCE(SUM(CASE WHEN ` + jobIsFailSQL + ` THEN 1 ELSE 0 END), 0) AS fail_count,
	COUNT(*) AS total_non_ok,
	COALESCE(MAX(created_at), 0) AS last_seen_at
FROM jobs
WHERE ` + jobFilterWhereClause + ` AND (` + jobIsNonOKSQL + `)
GROUP BY target
ORDER BY fail_count DESC, warn_count DESC, last_seen_at DESC
LIMIT ?;`
)

//nolint:gocritic // hugeParam: value filter matches JobStore contract.
func jobFilterArgs(filter JobFilter) []any {
	return []any{
		filter.ToolName, filter.ToolName,
		filter.Target, filter.Target,
		filter.TargetContains, filter.TargetContains,
		filter.Source, filter.Source,
		filter.Status, filter.Status, filter.Status,
		filter.Since, filter.Since,
		filter.Until, filter.Until,
		boolToInt(filter.IncidentsOnly),
	}
}

// SummarizeJobs computes SQLite aggregate metrics, top problem targets, and tool breakdowns for matching jobs.
//
//nolint:gocritic // hugeParam: value filter matches JobStore contract.
func (s *JobStore) SummarizeJobs(ctx context.Context, filter JobFilter) (*JobWindowSummary, error) {
	args := jobFilterArgs(filter)
	var summary JobWindowSummary
	err := s.roDB.QueryRowContext(ctx, summarizeJobsSQL, args...).Scan(
		&summary.TotalMatching,
		&summary.OKCount,
		&summary.WarnCount,
		&summary.FailCount,
		&summary.IncidentCount,
		&summary.AvgDurationMS,
		&summary.MinDurationMS,
		&summary.MaxDurationMS,
		&summary.EarliestCreatedAt,
		&summary.LatestCreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("summarize jobs: %w", err)
	}
	if summary.TotalMatching == 0 {
		return &summary, nil
	}
	summary.PassRatePct = math.Round(float64(summary.OKCount)/float64(summary.TotalMatching)*1000) / 10

	tools, err := s.queryToolBreakdown(ctx, args)
	if err != nil {
		return nil, err
	}
	summary.ToolBreakdown = tools

	targets, err := s.queryTopProblemTargets(ctx, args)
	if err != nil {
		return nil, err
	}
	summary.TopProblemTargets = targets

	return &summary, nil
}

func (s *JobStore) queryToolBreakdown(ctx context.Context, filterArgs []any) ([]ToolDigestCount, error) {
	args := append(append([]any{}, filterArgs...), toolBreakdownLimit)
	rows, err := s.roDB.QueryContext(ctx, toolBreakdownSQL, args...)
	if err != nil {
		return nil, fmt.Errorf("summarize tool breakdown: %w", err)
	}
	defer rows.Close()

	var out []ToolDigestCount
	for rows.Next() {
		var item ToolDigestCount
		if err := rows.Scan(
			&item.ToolName, &item.Total, &item.OKCount,
			&item.WarnCount, &item.FailCount, &item.AvgDurationMS,
		); err != nil {
			return nil, fmt.Errorf("scan tool breakdown: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tool breakdown: %w", err)
	}
	return out, nil
}

func (s *JobStore) queryTopProblemTargets(ctx context.Context, filterArgs []any) ([]TargetProblemCount, error) {
	args := append(append([]any{}, filterArgs...), topProblemTargetsLimit)
	rows, err := s.roDB.QueryContext(ctx, topProblemTargetsSQL, args...)
	if err != nil {
		return nil, fmt.Errorf("summarize top problem targets: %w", err)
	}
	defer rows.Close()

	var out []TargetProblemCount
	for rows.Next() {
		var item TargetProblemCount
		if err := rows.Scan(
			&item.Target, &item.WarnCount, &item.FailCount,
			&item.TotalNonOK, &item.LastSeenAt,
		); err != nil {
			return nil, fmt.Errorf("scan top problem targets: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate top problem targets: %w", err)
	}
	return out, nil
}
