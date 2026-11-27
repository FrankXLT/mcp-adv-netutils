#!/usr/bin/env python3
"""
scripts/build_github_showcase.py — Build & Privacy-Audit Public Static GitHub Pages Showcase.

Produces a self-contained, zero-backend Three-Route static bundle (`index.html`,
`demo/index.html`, `docs/index.html`) in `build/gh-pages/`:
  - `.nojekyll` + relative `./` / `../` asset URLs
  - Embedded 4-theme Operator Studio (`demo/index.html`) with `window.NETUTILS_STATIC_DEMO = true`,
    `demo/demo_snapshot.js`, unified 46px `OAW Projects` topbar, and `../assets/site.js`
  - Metadata-stripped PNGs (`tEXt`/`zTXt`/`iTXt`/`eXIf`/`tIME` chunks removed)
  - Fail-closed 0-leak privacy gate (`scan_showcase_privacy`)
"""
from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import re
import shutil
import struct
import sys
import tempfile
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_PNG_META_CHUNKS = frozenset({b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"})
_TEXT_EXTS = frozenset({".html", ".js", ".css", ".json", ".svg", ".md", ".webmanifest"})
_REQUIRED_ROUTES = ("index.html", "demo/index.html", "docs/index.html")
_DEMO_WEBUI_ASSETS = (
    "tokens.css",
    "studio.css",
    "charts.js",
    "studio_destinations.js",
    "studio_tool_views.js",
    "studio_results.js",
    "studio.js",
)
_DEMO_VENDOR_ASSETS = (
    "echarts.min.js",
    "quiet-evidence-bundle.js",
    "quiet-evidence-bundle.css",
)
_REQUIRED_DEMO_FILES = tuple(f"demo/{name}" for name in _DEMO_WEBUI_ASSETS) + tuple(
    f"demo/vendor/{name}" for name in _DEMO_VENDOR_ASSETS
)
_GENERIC_OS_USERS = frozenset({"dev", "root", "user", "runner", "ubuntu", "actions", "docker"})
_ALLOWED_MAC_PREFIXES = ("00:00:5e:00:53:", "02:42:00:00:02:")

_ALLOWED_PUBLIC_STRINGS = (
    "https://github.com/FrankXLT/mcp-adv-netutils",
    "github.com/FrankXLT/mcp-adv-netutils",
    "raw.githubusercontent.com/FrankXLT/mcp-adv-netutils",
    "https://FrankXLT.github.io/mcp-adv-netutils",
    "FrankXLT.github.io/mcp-adv-netutils",
    "ghcr.io/frankxlt/mcp-adv-netutils",
    "FrankXLT/mcp-adv-netutils",
    "https://github.com/FrankXLT",
    "@FrankXLT",
    "https://projects.oaworkbench.org/mcp-adv-netutils/",
    "https://projects.oaworkbench.org/agy-nexus-mcp/",
    "https://projects.oaworkbench.org/quiet-ui-skills/",
    "https://projects.oaworkbench.org/",
    "https://projects.oaworkbench.org",
    "https://learn.oaworkbench.org/",
    "https://learn.oaworkbench.org",
    "https://www.oaworkbench.org/",
    "https://www.oaworkbench.org",
    "@users.noreply.github.com",
    "/home/dev/",
    "/home/dev",
)

_LAN_RE = re.compile(r"\b[a-z0-9-]+\.lan\b", re.I)
_RFC1918_RE = re.compile(
    r"\b(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)
_MAC_RE = re.compile(r"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", re.I)
_HOME_PATH_RE = re.compile(r"/home/([A-Za-z0-9._-]+)")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def strip_png_metadata(src_path: Path, dst_path: Path) -> None:
    """Copy a PNG while stripping tEXt/zTXt/iTXt/eXIf/tIME ancillary metadata chunks."""
    data = src_path.read_bytes()
    if not data.startswith(_PNG_SIG):
        raise ValueError(f"Invalid PNG signature in {src_path}")
    chunks: list[bytes] = [_PNG_SIG]
    pos = len(_PNG_SIG)
    saw_iend = False
    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        ctype = data[pos + 4 : pos + 8]
        if length > len(data) - pos - 12:
            raise ValueError(f"Truncated/oversized PNG chunk in {src_path}")
        end = pos + 12 + length
        if ctype not in _PNG_META_CHUNKS:
            chunks.append(data[pos:end])
        pos = end
        if ctype == b"IEND":
            saw_iend = True
            break
    if not saw_iend:
        raise ValueError(f"Missing IEND chunk in {src_path}")
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    dst_path.write_bytes(b"".join(chunks))


def _copy_site_assets(src_dir: Path, dst_dir: Path) -> int:
    """Copy `site/assets/*` into `out_dir/assets/`, stripping metadata from any PNGs."""
    count = 0
    if not src_dir.is_dir():
        return count
    for src in sorted(src_dir.rglob("*")):
        if not src.is_file():
            continue
        rel = src.relative_to(src_dir)
        dst = dst_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.suffix.lower() == ".png":
            strip_png_metadata(src, dst)
        else:
            shutil.copy2(src, dst)
        count += 1
    return count


def _extract_demo_oaw_topbar(site_index_path: Path) -> str:
    """Extract `<header id="oawTopbar" ...>` from `site/index.html` and adapt relative paths for `./demo/`."""
    raw = site_index_path.read_text(encoding="utf-8")
    m = re.search(r'(<header\s+id="oawTopbar"\s+class="oaw-topbar"[^>]*>[\s\S]*?</header>)', raw)
    if not m:
        raise RuntimeError(f"Missing #oawTopbar header in {site_index_path}")
    bar = m.group(1)
    bar = (
        bar.replace('href="./demo/"', 'href="__OAW_DEMO__"', 2)
        .replace('href="./docs/"', 'href="../docs/"')
        .replace('href="./"', 'href="../"')
        .replace('href="__OAW_DEMO__"', 'href="./"')
    )
    bar = bar.replace(
        'class="oaw-pop-tab is-active" href="../" aria-current="page" data-oaw-tab="overview"',
        'class="oaw-pop-tab" href="../" data-oaw-tab="overview"',
    )
    bar = bar.replace(
        'class="oaw-pop-tab" href="./" data-oaw-tab="demo"',
        'class="oaw-pop-tab is-active" href="./" aria-current="page" data-oaw-tab="demo"',
    )
    bar = bar.replace(
        'class="oaw-context-tab is-active" href="../" aria-current="page" data-oaw-tab="overview"',
        'class="oaw-context-tab" href="../" data-oaw-tab="overview"',
    )
    bar = bar.replace(
        'class="oaw-context-tab" href="./" data-oaw-tab="demo"',
        'class="oaw-context-tab is-active" href="./" aria-current="page" data-oaw-tab="demo"',
    )
    if bar.count('aria-current="page" data-oaw-tab="demo"') != 2:
        raise RuntimeError("Failed to activate both desktop and mobile Demo tabs in #oawTopbar")
    return bar


def _rewrite_demo_index_for_static(html_text: str, topbar_html: str) -> str:
    """Inject OAW topbar, static demo snapshot flag/script, and site.js into `demo/index.html`."""
    out = html_text
    css_anchor = '<link rel="stylesheet" href="./studio.css">'
    if css_anchor not in out:
        raise RuntimeError("Missing ./studio.css link in internal/webui/assets/index.html")
    out = out.replace(
        css_anchor,
        f'<link rel="icon" href="../assets/icon.svg" type="image/svg+xml">\n  {css_anchor}\n  <link rel="stylesheet" href="../assets/oaw_topbar.css">',
        1,
    )

    charts_anchor = '<script defer src="./charts.js"></script>'
    studio_anchor = '<script defer src="./studio.js"></script>'
    if charts_anchor not in out or studio_anchor not in out:
        raise RuntimeError("Missing ./charts.js or ./studio.js script tags in internal/webui/assets/index.html")
    out = out.replace(
        charts_anchor,
        f'<script>window.NETUTILS_STATIC_DEMO = true;</script>\n  <script defer src="./demo_snapshot.js"></script>\n  {charts_anchor}',
        1,
    )
    out = out.replace(
        studio_anchor,
        f'{studio_anchor}\n  <script defer src="../assets/site.js"></script>',
        1,
    )

    if "<body>" not in out:
        raise RuntimeError("Missing <body> tag in internal/webui/assets/index.html")
    out = out.replace("<body>", f'<body class="oaw-demo-page">\n{topbar_html}', 1)
    return out


def _write_demo_snapshot_js(snapshot_json_path: Path, dst_js_path: Path) -> None:
    """Serialize `demo_snapshot.json` into `window.NETUTILS_DEMO_SNAPSHOT = <json>;\\n`."""
    payload = json.loads(snapshot_json_path.read_text(encoding="utf-8"))
    serialized = json.dumps(payload, ensure_ascii=False, indent=2).replace("</", "<\\/")
    dst_js_path.write_text(f"window.NETUTILS_DEMO_SNAPSHOT = {serialized};\n", encoding="utf-8")


def _load_privacy_inputs() -> tuple[set[str], set[str], set[str]]:
    """Collect OS usernames, secret literals from `~/.config/*/secrets.env`, and live brain UUIDs."""
    all_users: set[str] = set()
    for candidate in (Path.home().name, getpass.getuser()):
        cleaned = (candidate or "").strip().lower()
        if cleaned:
            all_users.add(cleaned)
    standalone_users = {u for u in all_users if len(u) >= 3 and u not in _GENERIC_OS_USERS}

    secrets: set[str] = set()
    cfg_root = Path.home() / ".config"
    if cfg_root.is_dir():
        for sec_path in sorted(cfg_root.glob("*/secrets.env")):
            if not sec_path.is_file():
                continue
            for line in sec_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = line.strip()
                if not s or s.startswith("#") or "=" not in s:
                    continue
                val = s.split("=", 1)[1].strip().strip("\"'")
                if len(val) >= 8 and "/" not in val:
                    secrets.add(val.lower())

    brain_dir = Path.home() / ".gemini" / "antigravity" / "brain"
    uuids: set[str] = set()
    if brain_dir.is_dir():
        uuids = {p.name.lower() for p in brain_dir.iterdir() if p.is_dir() and _UUID_RE.match(p.name)}
    return all_users | standalone_users, secrets, uuids


def _inspect_png_privacy(png_path: Path, tokens: set[str], rel: str) -> list[str]:
    """Verify PNG has no ancillary metadata chunks and no leaked secret/username bytes."""
    findings: list[str] = []
    raw = png_path.read_bytes()
    if not raw.startswith(_PNG_SIG):
        return [f"{rel}: invalid PNG header"]
    pos = len(_PNG_SIG)
    saw_iend = False
    while pos + 12 <= len(raw):
        length = struct.unpack(">I", raw[pos : pos + 4])[0]
        ctype = raw[pos + 4 : pos + 8]
        if length > len(raw) - pos - 12:
            findings.append(f"{rel}: truncated or oversized PNG chunk")
            break
        if ctype in _PNG_META_CHUNKS:
            findings.append(f"{rel}: disallowed PNG metadata chunk {ctype.decode('ascii', 'replace')}")
        pos += 12 + length
        if ctype == b"IEND":
            saw_iend = True
            break
    if not saw_iend:
        findings.append(f"{rel}: missing PNG IEND terminator")
    elif pos != len(raw):
        findings.append(f"{rel}: trailing bytes after PNG IEND ({len(raw) - pos} B)")
    low_bytes = raw.lower()
    for tok in tokens:
        if tok.encode("utf-8") in low_bytes:
            findings.append(f"{rel}: raw secret/username byte match")
    return findings


def _scan_text_file_privacy(
    fp: Path,
    rel: str,
    all_users: set[str],
    standalone_users: set[str],
    secrets: set[str],
    live_uuids: set[str],
) -> list[str]:
    """Scan one text asset for .lan domains, RFC1918 IPs, non-doc MACs, OS usernames, UUIDs, and secrets."""
    findings: list[str] = []
    txt = fp.read_text(encoding="utf-8", errors="ignore")

    for user_match in _HOME_PATH_RE.findall(txt):
        u_low = user_match.lower()
        if u_low != "dev" and (u_low in all_users or u_low not in _GENERIC_OS_USERS):
            findings.append(f"{rel}: leaked /home/{user_match} path")

    sanitized = txt
    for allow in sorted(_ALLOWED_PUBLIC_STRINGS, key=len, reverse=True):
        sanitized = sanitized.replace(allow, " ")
    low = sanitized.lower()

    for m in _LAN_RE.findall(sanitized):
        findings.append(f"{rel}: disallowed .lan domain `{m}`")
    for m in _RFC1918_RE.findall(sanitized):
        findings.append(f"{rel}: RFC1918 private IP `{m}`")
    for m in _MAC_RE.findall(sanitized):
        norm = m.lower().replace("-", ":")
        if not norm.startswith(_ALLOWED_MAC_PREFIXES):
            findings.append(f"{rel}: non-documentation MAC address `{m}`")
    for user in standalone_users:
        if re.search(rf"(?<![a-z0-9]){re.escape(user)}(?![a-z0-9])", low):
            findings.append(f"{rel}: leaked OS username literal")
    for u in live_uuids:
        if u in low:
            findings.append(f"{rel}: leaked live Antigravity brain UUID `{u[:8]}...`")
    for sec in secrets:
        if sec in low:
            findings.append(f"{rel}: leaked secret literal from ~/.config/*/secrets.env")
    return findings


def scan_showcase_privacy(out_dir: Path) -> list[str]:
    """Fail-closed scanner ensuring 0 leaked .lan domains, RFC1918 IPs, real MACs, usernames, UUIDs, secrets, or PNG metadata."""
    findings: list[str] = []
    all_users, secrets, live_uuids = _load_privacy_inputs()
    standalone_users = {u for u in all_users if len(u) >= 3 and u not in _GENERIC_OS_USERS}
    png_tokens = standalone_users | secrets

    for fp in sorted(out_dir.rglob("*")):
        if not fp.is_file():
            continue
        rel = fp.relative_to(out_dir).as_posix()
        if fp.suffix.lower() == ".png":
            findings.extend(_inspect_png_privacy(fp, png_tokens, rel))
        elif fp.suffix.lower() in _TEXT_EXTS or fp.name == ".nojekyll":
            findings.extend(_scan_text_file_privacy(fp, rel, all_users, standalone_users, secrets, live_uuids))
    return findings


def build_showcase(out_dir: Path) -> dict[str, Any]:
    """Assemble the static Three-Route Public Showcase in `out_dir`."""
    site_dir = REPO_ROOT / "site"
    webui_dir = REPO_ROOT / "internal" / "webui" / "assets"
    assets_out = out_dir / "assets"
    docs_out = out_dir / "docs"
    demo_out = out_dir / "demo"

    if out_dir.exists():
        shutil.rmtree(out_dir)
    for d in (out_dir, assets_out, docs_out, demo_out):
        d.mkdir(parents=True, exist_ok=True)
    (out_dir / ".nojekyll").write_text("", encoding="utf-8")

    shutil.copy2(site_dir / "index.html", out_dir / "index.html")
    shutil.copy2(site_dir / "docs" / "index.html", docs_out / "index.html")
    _copy_site_assets(site_dir / "assets", assets_out)

    for asset_name in _DEMO_WEBUI_ASSETS:
        shutil.copy2(webui_dir / asset_name, demo_out / asset_name)
    vendor_src = webui_dir / "vendor"
    if not vendor_src.is_dir():
        raise RuntimeError(f"Missing required vendor directory: {vendor_src}")
    shutil.copytree(vendor_src, demo_out / "vendor", dirs_exist_ok=True)

    _write_demo_snapshot_js(
        webui_dir / "demo_snapshots" / "demo_snapshot.json",
        demo_out / "demo_snapshot.js",
    )

    topbar_html = _extract_demo_oaw_topbar(site_dir / "index.html")
    demo_html = _rewrite_demo_index_for_static(
        (webui_dir / "index.html").read_text(encoding="utf-8"),
        topbar_html,
    )
    (demo_out / "index.html").write_text(demo_html, encoding="utf-8")

    missing = [r for r in (*_REQUIRED_ROUTES, *_REQUIRED_DEMO_FILES) if not (out_dir / r).is_file()]
    if missing:
        raise RuntimeError(f"Missing required showcase files: {', '.join(missing)}")

    files = [p for p in out_dir.rglob("*") if p.is_file()]
    return {
        "ok": True,
        "out_dir": str(out_dir),
        "routes": list(_REQUIRED_ROUTES),
        "files": len(files),
        "bytes": sum(p.stat().st_size for p in files),
    }


def _run_and_report(target: Path, *, check_mode: bool) -> int:
    res = build_showcase(target)
    findings = scan_showcase_privacy(target)
    if findings:
        print(f"[!] Privacy scan failed ({len(findings)} finding(s)):", file=sys.stderr)
        for item in findings[:20]:
            print(f"  - {item}", file=sys.stderr)
        return 1
    action = "Showcase check passed" if check_mode else f"Built showcase in {res['out_dir']}"
    print(
        f"[✓] {action} ({len(res['routes'])} routes, "
        f"{res['files']} files, {res['bytes']} B, 0 leaks)"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Build & privacy-audit static GitHub Pages showcase.")
    parser.add_argument(
        "--out",
        default=str(REPO_ROOT / "build" / "gh-pages"),
        help="Output directory (default: build/gh-pages)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Build in a temporary directory, verify routes & 0-leak privacy gate, and exit cleanly.",
    )
    args = parser.parse_args()

    try:
        if args.check:
            with tempfile.TemporaryDirectory(prefix="netutils-showcase-") as tmp_dir:
                return _run_and_report(Path(tmp_dir) / "gh-pages", check_mode=True)
        return _run_and_report(Path(args.out).resolve(), check_mode=False)
    except Exception as exc:
        print(f"[!] Showcase build failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
