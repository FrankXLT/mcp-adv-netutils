package webui

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/cronmon"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
)

const maxRecentStatuses = 8

var statusSeverity = map[string]int{"OK": 1, "WARN": 2, "FAIL": 3}

type durAgg struct {
	sum, max float64
	count    int64
}

type dailyKeyAgg struct {
	durAgg
	ok, warn, fail int64
}

type watchGroup struct {
	key, target, tool string
	jobKeys           map[string]struct{}
	merged            *store.CronStateRecord
}

func buildStripDays(daily []store.CronDailyStat) []stripDay {
	byDay := make(map[string]*dailyKeyAgg)
	for i := range daily {
		d := &daily[i]
		a := byDay[d.DayUTC]
		if a == nil {
			a = &dailyKeyAgg{}
			byDay[d.DayUTC] = a
		}
		ticks := d.OKCount + d.WarnCount + d.FailCount
		a.ok, a.warn, a.fail = a.ok+d.OKCount, a.warn+d.WarnCount, a.fail+d.FailCount
		a.sum, a.count = a.sum+d.AvgDurationMS*float64(ticks), a.count+ticks
	}
	days := slices.Sorted(maps.Keys(byDay))
	strip := make([]stripDay, 0, len(days))
	for _, day := range days {
		a, status, avg := byDay[day], "OK", 0.0
		if a.fail > 0 {
			status = "FAIL"
		} else if a.warn > 0 {
			status = "WARN"
		}
		if a.count > 0 {
			avg = roundTo(a.sum/float64(a.count), 2)
		}
		strip = append(strip, stripDay{Label: day, Status: status, AvgMs: avg, Detail: fmt.Sprintf("%d/%d ticks OK · avg %.1f ms", a.ok, a.count, avg)})
	}
	return strip
}

func buildWatchlistRows(items []cronmon.WatchItem, cronStatus *store.CronSummary, jobs []store.JobRecord) []watchlistRow {
	stateByKey, dailyByKey := make(map[string]*store.CronStateRecord), make(map[string]dailyKeyAgg)
	if cronStatus != nil {
		for i := range cronStatus.States {
			stateByKey[cronStatus.States[i].JobKey] = &cronStatus.States[i]
		}
		for i := range cronStatus.DailyStats {
			d := &cronStatus.DailyStats[i]
			ticks := d.OKCount + d.WarnCount + d.FailCount
			c := dailyByKey[d.JobKey]
			c.sum, c.count = c.sum+d.AvgDurationMS*float64(ticks), c.count+ticks
			c.ok, c.warn, c.fail = c.ok+d.OKCount, c.warn+d.WarnCount, c.fail+d.FailCount
			dailyByKey[d.JobKey] = c
		}
	}
	// jobs arrive newest-first from ListJobs; keep up to 8 statuses per pair and reverse to oldest -> newest.
	jobDur, recentByPair := make(map[string]durAgg), make(map[string][]string)
	for i := range jobs {
		j := &jobs[i]
		pk, d := normalizeWatchPair(j.ToolName, j.Target), float64(j.DurationMS)
		c := jobDur[pk]
		c.sum, c.count, c.max = c.sum+d, c.count+1, max(c.max, d)
		jobDur[pk] = c
		if len(recentByPair[pk]) < maxRecentStatuses {
			if st := strings.ToUpper(strings.TrimSpace(j.Status)); st != "" {
				recentByPair[pk] = append(recentByPair[pk], st)
			}
		}
	}
	for _, list := range recentByPair {
		slices.Reverse(list)
	}
	groups := make(map[string]*watchGroup, len(items)+len(stateByKey))
	order := make([]string, 0, len(items)+len(stateByKey))
	usedStates := make(map[string]struct{}, len(stateByKey))
	for i := range items {
		it := &items[i]
		st := stateByKey[it.Key]
		if st != nil {
			usedStates[it.Key] = struct{}{}
		}
		mergeWatchGroup(groups, &order, it.Key, it.Target, it.Tool, st)
	}
	for _, k := range slices.Sorted(maps.Keys(stateByKey)) {
		if _, ok := usedStates[k]; !ok && !strings.HasPrefix(k, "dest_") {
			st := stateByKey[k]
			mergeWatchGroup(groups, &order, st.JobKey, st.Target, st.ToolName, st)
		}
	}
	rows := make([]watchlistRow, 0, len(order))
	for _, pk := range order {
		rows = append(rows, makeWatchlistRow(groups[pk], dailyByKey, jobDur[pk], recentByPair[pk]))
	}
	return rows
}

func normalizeWatchPair(tool, target string) string {
	return strings.ToLower(strings.TrimSpace(tool)) + "\x00" + strings.ToLower(strings.TrimSpace(target))
}

func mergeWatchGroup(groups map[string]*watchGroup, order *[]string, key, target, tool string, st *store.CronStateRecord) {
	pk := normalizeWatchPair(tool, target)
	g := groups[pk]
	if g == nil {
		g = &watchGroup{key: key, target: target, tool: tool, jobKeys: map[string]struct{}{key: {}}}
		groups[pk] = g
		*order = append(*order, pk)
	} else if key != "" {
		g.jobKeys[key] = struct{}{}
		if g.key == "" || (strings.HasPrefix(g.key, "dest_") && !strings.HasPrefix(key, "dest_")) {
			g.key = key
		}
	}
	if st == nil {
		return
	}
	if g.merged == nil {
		cp := *st
		g.merged = &cp
		return
	}
	if st.LastTickAt > g.merged.LastTickAt {
		cp := *st
		g.merged = &cp
		return
	}
	if st.LastTickAt < g.merged.LastTickAt {
		return
	}
	g.merged.ActiveAlert = g.merged.ActiveAlert || st.ActiveAlert
	g.merged.ConsecutiveNonOK = max(g.merged.ConsecutiveNonOK, st.ConsecutiveNonOK)
	if statusSeverity[strings.ToUpper(strings.TrimSpace(st.LastStatus))] > statusSeverity[strings.ToUpper(strings.TrimSpace(g.merged.LastStatus))] {
		g.merged.LastStatus = st.LastStatus
	}
}

func makeWatchlistRow(g *watchGroup, dailyByKey map[string]dailyKeyAgg, jobStat durAgg, recent []string) watchlistRow {
	health, hyst, lastTick := "OK", "Healthy", ""
	if g.merged != nil {
		if s := strings.ToUpper(strings.TrimSpace(g.merged.LastStatus)); s != "" {
			health = s
		}
		switch {
		case g.merged.ActiveAlert || g.merged.ConsecutiveNonOK >= 2:
			hyst = "Alerting"
		case g.merged.ConsecutiveNonOK == 1:
			hyst = "1 failed check"
		}
		if g.merged.LastTickAt > 0 {
			lastTick = time.Unix(g.merged.LastTickAt, 0).UTC().Format(time.RFC3339)
		}
	}
	var dailySum float64
	var dailyCount, ok, warn, fail int64
	for jk := range g.jobKeys {
		a := dailyByKey[jk]
		dailySum, dailyCount = dailySum+a.sum, dailyCount+a.count
		ok, warn, fail = ok+a.ok, warn+a.warn, fail+a.fail
	}
	var avgMS, maxMS float64
	if dailyCount > 0 {
		avgMS = roundTo(dailySum/float64(dailyCount), 2)
	}
	if jobStat.count > 0 {
		if avgMS == 0 {
			avgMS = roundTo(jobStat.sum/float64(jobStat.count), 2)
		}
		maxMS = roundTo(jobStat.max, 2)
	}
	if maxMS == 0 && avgMS > 0 {
		maxMS = avgMS
	}
	if len(recent) == 0 {
		recent = fallbackRecentStatuses(ok, warn, fail, health, lastTick)
	}
	return watchlistRow{
		Key: g.key, Target: g.target, Check: g.tool, Health: health, Hysteresis: hyst,
		AvgMS: avgMS, MaxMS: maxMS, LastTick: lastTick, RecentStatuses: recent,
	}
}

func fallbackRecentStatuses(ok, warn, fail int64, health, lastTick string) []string {
	total := ok + warn + fail
	if total == 0 {
		if lastTick != "" {
			return []string{health}
		}
		return nil
	}
	n := int(min(total, maxRecentStatuses))
	failSlots := int((fail*int64(n) + total/2) / total)
	if fail > 0 && failSlots == 0 {
		failSlots = 1
	}
	warnSlots := min(max(0, n-failSlots), int((warn*int64(n)+total/2)/total))
	if warn > 0 && warnSlots == 0 && failSlots < n {
		warnSlots = 1
	}
	counts := [3]int{n - failSlots - warnSlots, warnSlots, failSlots}
	labels := [3]string{"OK", "WARN", "FAIL"}
	out := make([]string, 0, n)
	for idx := range 3 {
		i := idx
		if health == "OK" {
			i = 2 - idx
		}
		out = append(out, slices.Repeat([]string{labels[i]}, counts[i])...)
	}
	return out
}
