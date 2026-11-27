---
name: netutils-ascii-display
description: Format, render, and present mcp-adv-netutils diagnostic output using deterministic ASCII/TUI styles (default, quick, rich, json), verbatim fenced text blocks, and render_run_digest.
---

# `netutils-ascii-display`

Operational playbook for rendering `mcp-adv-netutils` diagnostic results with deterministic column widths, clean mobile readability, and structured JSON fallback.

## Style Reference

Pass the `style` parameter on supported diagnostic recipes or `render_run_digest`:

| `style` | Width / Size | Layout | Intended Client |
| :--- | :--- | :--- | :--- |
| `default` | **72 cols exact** | Compact single-line sections, aligned status badges | Desktop chat, terminal logs |
| `quick` | **`<= 40` cols** | Borderless, minimal labels, zero horizontal scroll | Mobile (`390px` viewport), narrow panes |
| `rich` | **76 cols exact** | Boxed TUI (`+---+` / Unicode box frames), sparklines & histograms | Wide terminals, incident reports |
| `json` | **`< 18.5 KB`** | Structured payload with `FAIL` and `WARN` entries sorted first | Programmatic pipelines, UI studio |

### Sorting & Truncation Rules (`json`)
- Results are ordered by severity: `FAIL` -> `WARN` -> `OK` / `INFO`.
- Payload size is capped strictly below `18.5 KB` so tool outputs remain within MCP transport and context budgets. When trimming is required, healthy `OK` detail rows are compacted first while preserving all `FAIL` and `WARN` findings.

## Mandatory Verbatim Presentation Rule

Always wrap `default`, `quick`, and `rich` ASCII output verbatim inside a fenced `text` code block:

````markdown
```text
[paste exact tool output here without re-indenting or reflowing]
```
````

- **Never** wrap ASCII tables in proportional Markdown prose, blockquotes, or regular Markdown tables.
- **Never** add trailing spaces, re-wrap lines, or strip box-drawing characters.
- For `390px` mobile chats or tight notification cards, always choose `style: "quick"` so lines never exceed `40` columns.

## Re-Rendering Persisted Runs (`render_run_digest`)

Use `render_run_digest` whenever you have a stored `job_id` / run ID (from `get_cron_status`, `get_job_report`, or a previous recipe call) and need to view it in a different `style`:

1. **Mobile Triage**: Call `render_run_digest` with `style: "quick"` (`<= 40` cols) for quick status checks on phones.
2. **Incident Review**: Call `render_run_digest` with `style: "rich"` (`76` cols) to inspect boxed hop ladders, latency histograms, and full badge context.
3. **Automation / Diffing**: Call `render_run_digest` with `style: "json"` (`< 18.5 KB`) to inspect sorted `FAIL`/`WARN` records programmatically.

## Quick Decision Checklist

- Is the user on mobile or asking for a quick summary? -> `style: "quick"` (`<= 40` cols).
- Standard desktop / agent summary? -> `style: "default"` (`72` cols).
- Deep path/sweep review or archived postmortem? -> `style: "rich"` (`76` cols).
- Need machine-readable triage sorted by severity? -> `style: "json"` (`< 18.5 KB`).
