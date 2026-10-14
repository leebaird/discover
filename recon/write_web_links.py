#!/usr/bin/env python3
# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
"""Write web.htm next to a host-scan artifact.

The page is a list of ordinary links. Edge on Windows can open it the same
way it opens a Nikto htm report. Firefox on the Discover host still uses the
discover-* desktop handlers; this file is the fallback those handlers do not
need.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

_WRITTEN: set[str] = set()


def urls_from_lines(path: Path) -> list[str]:
    """Unique http(s) lines, in file order. Skips blanks and # comments."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    seen: set[str] = set()
    urls: list[str] = []
    for raw in text.splitlines():
        url = raw.strip()
        if not url or url.startswith("#"):
            continue
        if not url.startswith(("http://", "https://")):
            continue
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def urls_from_findings_json(path: Path) -> list[str]:
    """ffuf results JSON, or feroxbuster NDJSON. Same rules as open-ffuf-tabs.sh."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    data = None
    try:
        data = json.loads(text) if text else None
    except Exception:
        data = None

    seen: set[str] = set()
    urls: list[str] = []

    def add(url: object) -> None:
        u = str(url or "").strip()
        if not u.startswith(("http://", "https://")):
            return
        if u in seen:
            return
        seen.add(u)
        urls.append(u)

    if isinstance(data, dict):
        for row in data.get("results") or []:
            if isinstance(row, dict):
                add(row.get("url"))
        add(data.get("url"))
    elif isinstance(data, list):
        for row in data:
            if isinstance(row, dict):
                add(row.get("url"))

    if not urls:
        for raw in text.splitlines():
            raw = raw.strip()
            if not raw or raw[0] not in "{[":
                continue
            try:
                row = json.loads(raw)
            except Exception:
                continue
            if not isinstance(row, dict):
                continue
            if row.get("type") and row.get("type") != "response":
                continue
            add(row.get("url") or row.get("original_url"))
    return urls


def urls_for(path: Path, tool: str) -> list[str]:
    if tool in ("ffuf", "feroxbuster"):
        return urls_from_findings_json(path)
    return urls_from_lines(path)


def write_page(dest: Path, heading: str, urls: list[str]) -> bool:
    """Write dest. Returns False when there is nothing to list."""
    if not urls:
        return False
    key = str(dest)
    if key in _WRITTEN:
        return True
    n = len(urls)
    if n == 1:
        lead = "1 URL. The link opens in a new tab."
    else:
        lead = f"{n} URLs. Each link opens in a new tab."
    items = "\n".join(
        '<li><a href="{href}" target="_blank" rel="noopener">{text}</a></li>'.format(
            href=html.escape(url, quote=True),
            text=html.escape(url),
        )
        for url in urls
    )
    doc = (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{html.escape(heading)}</title>\n"
        "<style>\n"
        "body { font-family: sans-serif; margin: 24px; color: #1b1b1b; }\n"
        "h1 { font-size: 20px; font-weight: 600; margin: 0 0 8px; }\n"
        "p { margin: 0 0 16px; }\n"
        "ol { margin: 0; padding-left: 24px; }\n"
        "li { margin: 6px 0; }\n"
        "a { color: #0b57d0; word-break: break-all; }\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        f"<h1>{html.escape(heading)}</h1>\n"
        f"<p>{lead}</p>\n"
        "<ol>\n"
        f"{items}\n"
        "</ol>\n"
        "</body>\n"
        "</html>\n"
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(doc, encoding="utf-8")
    _WRITTEN.add(key)
    return True


_HEADINGS = {
    "robots": "robots.txt Disallow directories",
    "ffuf": "ffuf findings",
    "feroxbuster": "feroxbuster findings",
    "nmap": "nmap HTTP(S) ports",
}
_SOURCES = {
    "ffuf": "ffuf.json",
    "feroxbuster": "ferox.json",
    "nmap": "web-urls.txt",
}


def _robots_dir_urls(path: Path) -> list[str]:
    """Disallow URLs that are not the site root. Query-string paths stay."""
    from urllib.parse import urlparse

    kept: list[str] = []
    for url in urls_from_lines(path):
        parsed = urlparse(url)
        path_only = (parsed.path or "/").rstrip("/") or "/"
        if path_only == "/" and not (parsed.query or parsed.fragment):
            continue
        kept.append(url)
    return kept


def _tool_urls(run_dir: Path, tool: str) -> list[str] | None:
    """URLs for WEB, or None when the source file is missing."""
    if tool == "robots":
        src = run_dir / "disallow-urls.txt"
        if not src.is_file():
            return None
        return _robots_dir_urls(src)
    filename = _SOURCES.get(tool)
    if not filename:
        return None
    src = run_dir / filename
    if not src.is_file():
        return None
    if tool == "nmap":
        return urls_from_lines(src)
    return urls_from_findings_json(src)


def prepare_client_subdomains(stage: Path) -> None:
    """Client export only. Adjust the staged copy so Subdomains can show tools.

    Writes status.js and any missing web.htm under stage. Does not modify the
    live engagement. The page flag hides Run and the info button.
    """
    stage = Path(stage)
    scans = stage / "tools" / "host-scans"
    status_path = scans / "status.json"
    if not status_path.is_file():
        return
    try:
        status = json.loads(status_path.read_text(encoding="utf-8"))
    except Exception:
        return
    if not isinstance(status, dict):
        return
    hosts = status.get("hosts")
    if not isinstance(hosts, dict):
        hosts = {}
        status["hosts"] = hosts

    for host, tools in hosts.items():
        if not isinstance(tools, dict):
            continue
        for tool, st in tools.items():
            if not isinstance(st, dict):
                continue
            rel = str(st.get("output_rel") or st.get("output") or "").lstrip("/")
            if rel and not (stage / rel).is_file():
                txt = rel
                if tool == "robots":
                    txt = str(Path(rel).with_name("robots.txt"))
                if not (stage / txt).is_file():
                    st.pop("output", None)
                    st.pop("output_rel", None)
                    rel = ""
            if tool not in _HEADINGS or not rel:
                continue
            run_dir = (stage / rel).parent
            urls = _tool_urls(run_dir, tool)
            if urls is None:
                if st.get("url_count") is None:
                    st["url_count"] = 0
                continue
            st["url_count"] = len(urls)
            if urls:
                write_page(run_dir / "web.htm", _HEADINGS[tool], urls)

    js_payload = json.dumps(status, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    scans.mkdir(parents=True, exist_ok=True)
    (scans / "status.js").write_text(
        "window.DISCOVER_HOST_SCAN_STATUS=" + js_payload + ";\n",
        encoding="utf-8",
    )

    page = stage / "pages" / "subdomains.htm"
    if not page.is_file():
        return
    import re

    text = page.read_text(encoding="utf-8", errors="replace")
    text = text.replace('<script src="../tools/host-scans/status.js"></script>\n', "")
    text = text.replace("<script>window.DISCOVER_CLIENT_VIEW=true;</script>\n", "")
    tag_re = re.compile(
        r'<script src="\.\./assets/javascript/inc-host-scan\.js\?v=\d+"></script>'
    )
    match = tag_re.search(text)
    if not match:
        return
    block = (
        '<script src="../tools/host-scans/status.js"></script>\n'
        "<script>window.DISCOVER_CLIENT_VIEW=true;</script>\n"
        + match.group(0)
    )
    text = text[: match.start()] + block + text[match.end() :]
    page.write_text(text, encoding="utf-8")
