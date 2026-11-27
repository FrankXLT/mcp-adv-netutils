---
name: netutils-cron-monitor
description: Monitor scheduled watchlist checks and saved destinations across the 33-tool suite with get_cron_status (24h/7d/30d), manage_cron_watchlist, manage_saved_destinations (list/save/delete/run + dest_<id> watchlist sync), get_job_report (30d retention and expires_at), Two-Tick Alert Hysteresis, and 7d-to-30d down-aging.
---

# `netutils-cron-monitor`

Operational playbook for operating the `mcp-adv-netutils` scheduled watchlist daemon, managing Saved Destinations, reviewing uptime rollups, and inspecting job report retention.

## Core Tools

| Tool | Purpose |
| :--- | :--- |
| `get_cron_status` | Returns watchlist health summary for `24h`, `7d`, or `30d` windows |
| `manage_cron_watchlist` | Lists, adds, updates, pauses, resumes, or removes scheduled checks |
| `manage_saved_destinations` | `list` \| `save` \| `delete` \| `run` persisted targets with `dest_<id>` cron watchlist sync |
| `get_job_report` | Fetches full stored execution details (`30d` retention + `expires_at` countdown) |

## Reviewing Scheduled Health (`get_cron_status`)

Call `get_cron_status` with the desired rollup window:
- **`24h`**: Immediate operational view—active incidents, recent latency deltas, and consecutive failure counts.
- **`7d`**: Short-term stability trends—catches nightly flaps, certificate renewal warnings, or intermittent WAN jitter.
- **`30d`**: Monthly SLA/uptime rollup—inspects long-term reliability using compacted healthy tick history.

Use `style: "quick"` (`<= 40` cols) on mobile or `style: "default"` / `"rich"` for desktop triage.

## Two-Tick Alert Hysteresis

To eliminate alert fatigue from single-packet WAN blips or transient container restarts, `mcp-adv-netutils` enforces **Two-Tick Alert Hysteresis**:

- **1st non-OK tick**: Recorded as a soft `WARN` / pending anomaly (`consecutive_failures = 1`). **No alert is emitted.**
- **`>= 2` consecutive non-OK ticks**: Escalates state to `FAIL` / alerting, confirming a persistent condition rather than single-probe jitter.
- **Recovery**: A subsequent `OK` tick resets the consecutive non-OK counter and clears the alert state.

When triaging a `WARN` in `get_cron_status`, check whether it is a single-tick blip or an active `>= 2`-tick streak before escalating.

## Inspecting Detailed Runs (`get_job_report`)

1. Locate the `job_id` from `get_cron_status` or recipe output.
2. Call `get_job_report` to retrieve the full persisted diagnostic output, timestamps, and status history.
3. Note the **`30d` retention window** and **`expires_at` countdown**:
   - Job reports are stored in SQLite (`netutils_jobs.db`) for **30 days** (`30d`).
   - `expires_at` indicates exactly how much time remains before automatic TTL pruning removes the record.
   - Re-render any stored job report into a different display format (`default`, `quick`, `rich`, `json`) using `render_run_digest`.

## `7d -> 30d` Healthy Tick Down-Aging

To keep `netutils_jobs.db` compact without losing SLA history:
- Granular per-tick healthy (`OK`) records are kept for **`7 days`**.
- After **7 days (`7d -> 30d`)**, healthy ticks are **down-aged** into rolled-up aggregate summaries (pass count, min/avg/max latency) retained through the full **30-day** window.
- Non-OK (`WARN` / `FAIL`) diagnostic records retain full failure context throughout the 30-day retention lifecycle.

## Managing Checks & Saved Destinations (`manage_cron_watchlist` & `manage_saved_destinations`)

- **`manage_cron_watchlist`**: Inspect loaded `watchlist.yaml` entries, pause noisy checks during planned maintenance, or add/update probe schedules.
- **`manage_saved_destinations`**: Manage persistent `saved_destinations` rows in `netutils_jobs.db` (`action`: `list` | `save` | `delete` | `run`):
  - Enforces `TargetGuard` CIDR/scheme validation on every saved target (`IP`, `hostname`, `CIDR`, or `URL`).
  - When `monitor_enabled` is toggled on, automatically creates/updates a matching `dest_<id>` entry (`*/5 * * * *` default) in the cron watchlist; toggling off or deleting removes `dest_<id>` from the schedule.
  - Supports optional `mac` (Wake MAC), `category`, `default_check`, and `pinned` flags used by the `/web` Pinned Destinations bar and **Scan Pinned** sweep.
  - Mutations (`save`, `delete`, and watchlist edits) require unlocking the Thirty-Minute Passphrase Deadbolt via `unlock_netutils` when `PASS_HASH` is configured.
