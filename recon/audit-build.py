#!/usr/bin/env python3
# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
"""Build Audit page HTML for a Discover engagement report."""

from __future__ import annotations

import html
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import quote, urlparse

# New: time | operator | ip | action
LINE_RE4 = re.compile(
    r"^(\d{2}-\d{2}-\d{4} Z - \d{2}:\d{2}) \| ([^|]+) \| ([^|]+) \| (.*)$"
)
# Legacy: time | ip | action
LINE_RE3 = re.compile(
    r"^(\d{2}-\d{2}-\d{4} Z - \d{2}:\d{2}) \| ([^|]+) \| (.*)$"
)

# Host-scan tools: storage key → display label (quietest → loudest).
# droopescan / wpscan are gated on the Subdomains panel (CMS / WordPress)
# but always appear as Target scans columns so prior runs remain visible.
HOST_SCAN_TOOLS: list[tuple[str, str]] = [
    ("nuclei", "Nuclei"),
    ("droopescan", "droopescan"),
    ("wpscan", "WPScan"),
    ("nikto", "Nikto"),
    ("ffuf", "ffuf"),
]

# Known export kinds / common labels → display text on the Audit page.
EXPORT_KIND_DISPLAY = {
    "client": "Client",
    "defender": "Defender",
    "defenders": "Defenders",
    "audit-only": "Audit only",
    "operator": "Operator",
}

EXPORT_LABEL_DISPLAY = {
    "briefing": "Briefing",
    "defenders": "Defenders",
    "defender": "Defender",
    "client": "Client",
    "update": "Update",
    "audit-only": "Audit only",
}


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def format_export_kind(kind: str) -> str:
    key = (kind or "").strip().lower()
    if key in EXPORT_KIND_DISPLAY:
        return EXPORT_KIND_DISPLAY[key]
    if not key:
        return "—"
    # Title-case hyphenated tokens: "audit-only" already mapped; others → "Some Kind"
    return " ".join(part.capitalize() for part in key.replace("_", "-").split("-"))


def format_export_label(label: str) -> str:
    raw = (label or "").strip()
    if not raw:
        return "—"
    key = raw.lower()
    if key in EXPORT_LABEL_DISPLAY:
        return EXPORT_LABEL_DISPLAY[key]
    # Preserve multi-word freeform labels with simple title case
    return " ".join(part.capitalize() for part in raw.replace("_", " ").replace("-", " ").split())


def format_export_time(exp: dict) -> str:
    """Match audit log times: mm-dd-yyyy Z - hh:mm (UTC)."""
    display = (exp.get("exported_at_display") or "").strip()
    if display and " Z - " in display:
        return display

    raw = (exp.get("exported_at_utc") or display or "").strip()
    if not raw:
        return "—"

    # Already audit-log style
    if " Z - " in raw:
        return raw

    # ISO-8601 UTC: 2026-07-16T00:37:51Z or with offset
    try:
        from datetime import datetime, timezone

        cleaned = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%m-%d-%Y Z - %H:%M")
    except Exception:
        return raw


def _audit_action_hidden(action: str) -> bool:
    """Skip routine noise on the Audit page."""
    a = (action or "").strip().rstrip(".").lower()
    if a.startswith("opened report in discover"):
        return True
    # Pass-2 start/finish are redundant with the parent nuclei lines + Output links.
    if "nuclei pass-2" in a or "nuclei pass 2" in a:
        return True
    return False


def _normalize_audit_action(action: str) -> str:
    """Light cleanup on stored action text (still used for Target/Output parse)."""
    text = (action or "").strip()
    # "(exit 0)" / "(exit 0)." mid-string or before other notes
    text = re.sub(r"\s*\(exit\s+0\)\s*", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\s{2,}", " ", text).strip()
    return text


def _extract_command_from_output_text(text: str) -> str:
    """First Command: block from a host-scan output.txt (run-host-scan header)."""
    lines = (text or "").splitlines()
    for i, line in enumerate(lines):
        if line.strip() != "Command:":
            continue
        parts: list[str] = []
        for j in range(i + 1, len(lines)):
            s = lines[j].strip()
            if not s:
                if parts:
                    break
                continue
            if s.startswith("===") or s in {
                "Results:",
                "Findings:",
                "Output:",
                "HTML report:",
                "JSON results:",
                "CMS:",
                "Software:",
            }:
                break
            if s.startswith("Results:") or s.startswith("Findings:"):
                break
            parts.append(s)
        if parts:
            return " ".join(parts)
    return ""


def _command_for_host_scan(
    report_root: Path,
    host: str,
    tool: str,
    audit_ts: str,
    scan_index: dict[str, dict[str, dict]],
) -> str:
    """Resolve exact Command line for a Started host-scan audit event."""
    host = (host or "").lower()
    tool = (tool or "").lower()
    if tool.startswith("nuclei pass"):
        tool = "nuclei"
    if not host or tool not in {"ffuf", "nikto", "nuclei", "droopescan", "wpscan"}:
        return ""

    base = report_root / "tools" / "host-scans" / host / tool
    candidates: list[Path] = []

    # Prefer run whose output Started: timestamp matches the audit line.
    if base.is_dir():
        for run_dir in sorted(base.iterdir(), reverse=True):
            if not run_dir.is_dir() or run_dir.name == "latest.json":
                continue
            out = run_dir / "output.txt"
            if out.is_file():
                candidates.append(out)

    meta = (scan_index.get(host) or {}).get(tool) or {}
    rel = str(meta.get("output") or meta.get("output_rel") or "").strip()
    if rel:
        p = report_root / rel.lstrip("/")
        if p.is_file() and p not in candidates:
            candidates.insert(0, p)

    audit_ts = (audit_ts or "").strip()
    for out in candidates:
        try:
            text = out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if audit_ts and f"Started: {audit_ts}" not in text:
            # Keep scanning other runs; fall back to any command if none match.
            continue
        cmd = _extract_command_from_output_text(text)
        if cmd:
            return cmd

    # No timestamp match — use newest file that has a Command block.
    for out in candidates:
        try:
            text = out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        cmd = _extract_command_from_output_text(text)
        if cmd:
            return cmd
    return ""


def _display_audit_action(
    action: str,
    *,
    report_root: Path | None = None,
    scan_index: dict[str, dict[str, dict]] | None = None,
    ts: str = "",
) -> str:
    """Action column: Started → exact Command; Finished → short verb+tool."""
    text = _normalize_audit_action(action)
    if not text:
        return text

    m = re.match(
        r"(?i)^(started|finished)\s+"
        r"(nuclei(?:\s+pass-2)?|droopescan|wpscan|ffuf|nikto)\b",
        text,
    )
    if m:
        verb = m.group(1).lower()
        tool_raw = re.sub(r"\s+", " ", m.group(2).strip().lower())
        if verb == "started" and report_root is not None:
            scan_m = _AUDIT_SCAN_ACTION_RE.search(action or "")
            host = ""
            if scan_m:
                host = _hostname_from_url(scan_m.group("url").rstrip(".,;"))
            tool = "nuclei" if tool_raw.startswith("nuclei") else tool_raw
            cmd = _command_for_host_scan(
                report_root,
                host,
                tool,
                ts,
                scan_index or {},
            )
            if cmd:
                return cmd
            return f"Started {tool_raw}."

        # Finished …
        tool = tool_raw
        exit_m = re.search(r"\(exit\s+(\d+)\)", text, re.I)
        if exit_m and exit_m.group(1) != "0":
            return f"Finished {tool} (exit {exit_m.group(1)})."
        return f"Finished {tool}."

    # Ran Shodan enrichment (long stats…). → Ran Shodan enrichment.
    if re.match(r"(?i)^ran shodan enrichment\b", text):
        return "Ran Shodan enrichment."

    if text.endswith("."):
        return text
    return text + "."


def load_audit_lines(report_root: Path) -> list[tuple[str, str, str, str]]:
    """Return (time, operator, ip, action). Legacy 3-field lines use empty operator."""
    log = report_root / "tools" / "audit" / "log.txt"
    if not log.is_file():
        return []
    rows = []
    for raw in log.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        m4 = LINE_RE4.match(raw)
        if m4:
            action = _normalize_audit_action(m4.group(4).strip())
            if _audit_action_hidden(action):
                continue
            rows.append(
                (
                    m4.group(1),
                    m4.group(2).strip(),
                    m4.group(3).strip(),
                    action,
                )
            )
            continue
        m3 = LINE_RE3.match(raw)
        if m3:
            action = _normalize_audit_action(m3.group(3).strip())
            if _audit_action_hidden(action):
                continue
            # Legacy: second field is IP (no operator name).
            rows.append((m3.group(1), "", m3.group(2).strip(), action))
        else:
            if _audit_action_hidden(raw):
                continue
            rows.append(("", "", "", _normalize_audit_action(raw)))
    rows.reverse()  # newest first
    return rows


def load_host_scan_summary(report_root: Path) -> list[dict]:
    base = report_root / "tools" / "host-scans"
    if not base.is_dir():
        return []

    status = load_json(base / "status.json", {})
    hosts = status.get("hosts") if isinstance(status, dict) else None
    if isinstance(hosts, dict) and hosts:
        rows = []
        for host, tools in hosts.items():
            if not isinstance(tools, dict):
                continue
            rows.append(
                {
                    "host": host,
                    "tools": tools,
                }
            )
        rows.sort(key=lambda r: r["host"])
        return rows

    # Fallback: walk directories
    rows = []
    for host_dir in sorted(base.iterdir()):
        if not host_dir.is_dir() or host_dir.name.startswith("."):
            continue
        tools = {}
        for tool, _label in HOST_SCAN_TOOLS:
            latest = host_dir / tool / "latest.json"
            if latest.is_file():
                tools[tool] = load_json(latest, {})
        if tools:
            rows.append({"host": host_dir.name, "tools": tools})
    return rows


def load_exports(report_root: Path) -> list[dict]:
    path = report_root / "tools" / "exports" / "log.jsonl"
    if not path.is_file():
        return []
    rows = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            rows.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    rows.reverse()
    return rows


def _pages_href(path_from_report_root: str) -> str:
    """Href from pages/*.htm into the report tree."""
    rel = str(path_from_report_root).lstrip("/")
    if not rel.startswith("../"):
        rel = "../" + rel
    return rel


# Audit log Action → host-scan tool / pass-2 / URL (for Output column links).
_AUDIT_SCAN_ACTION_RE = re.compile(
    r"(?i)\b(?P<verb>started|finished)\s+"
    r"(?P<tool>nuclei\s+pass-2|droopescan|wpscan|ffuf|nikto|nuclei)\b"
    r".*?\bon\s+(?P<url>https?://[^\s)(]+)"
)


def _hostname_from_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def audit_target_from_action(action: str) -> str:
    """Host/target for audit log Target column (host scans only)."""
    m = _AUDIT_SCAN_ACTION_RE.search(action or "")
    if not m:
        return ""
    url = m.group("url").rstrip(".,;")
    return _hostname_from_url(url)


def build_host_scan_output_index(report_root: Path) -> dict[str, dict[str, dict]]:
    """host -> tool -> latest meta dict (status/output paths)."""
    index: dict[str, dict[str, dict]] = {}
    for row in load_host_scan_summary(report_root):
        host = (row.get("host") or "").lower()
        tools = row.get("tools") if isinstance(row.get("tools"), dict) else {}
        if not host:
            continue
        index[host] = {k: v for k, v in tools.items() if isinstance(v, dict)}
    return index


def audit_output_cell(
    action: str,
    report_root: Path,
    scan_index: dict[str, dict[str, dict]],
) -> str:
    """Output column: scan / htm / pass2 buttons when the action is a host scan."""
    m = _AUDIT_SCAN_ACTION_RE.search(action or "")
    if not m:
        return '<span class="inc-audit-muted">—</span>'

    tool_raw = re.sub(r"\s+", " ", m.group("tool").strip().lower())
    url = m.group("url").rstrip(".,;")
    host = _hostname_from_url(url)
    if not host:
        return '<span class="inc-audit-muted">—</span>'

    is_pass2 = tool_raw.startswith("nuclei pass-2") or tool_raw == "nuclei pass-2"
    tool = "nuclei" if is_pass2 or tool_raw == "nuclei" else tool_raw
    if tool not in {"ffuf", "nikto", "nuclei", "droopescan", "wpscan"}:
        return '<span class="inc-audit-muted">—</span>'

    meta = (scan_index.get(host) or {}).get(tool) or {}
    output = str(meta.get("output") or meta.get("output_rel") or "").strip()
    status = (meta.get("status") or "").lower()

    if status == "running" and not is_pass2:
        return '<span class="inc-audit-running">Running…</span>'

    links: list[str] = []
    if is_pass2:
        # nuclei-pass2.txt lives next to output.txt for the latest nuclei run
        if output:
            pass2_rel = str(Path(output).with_name("nuclei-pass2.txt")).replace("\\", "/")
            pass2_disk = report_root / pass2_rel.lstrip("/")
            if pass2_disk.is_file() and pass2_disk.stat().st_size > 0:
                href = _pages_href(pass2_rel)
                links.append(
                    f'<a class="inc-audit-btn" href="{html.escape(href, quote=True)}" '
                    f'target="_blank" rel="noopener">txt</a>'
                )
            elif pass2_disk.is_file():
                # empty file = templates ran, no hits — still linkable
                href = _pages_href(pass2_rel)
                links.append(
                    f'<a class="inc-audit-btn" href="{html.escape(href, quote=True)}" '
                    f'target="_blank" rel="noopener">txt</a>'
                )
        if not links:
            return '<span class="inc-audit-muted">—</span>'
    else:
        if output:
            href = _pages_href(output)
            links.append(
                f'<a class="inc-audit-btn" href="{html.escape(href, quote=True)}" '
                f'target="_blank" rel="noopener">txt</a>'
            )
            if tool == "nikto":
                htm_rel = str(Path(output).with_name("nikto.htm")).replace("\\", "/")
                htm_disk = report_root / htm_rel.lstrip("/")
                if htm_disk.is_file():
                    links.append(
                        f'<a class="inc-audit-btn" href="{html.escape(_pages_href(htm_rel), quote=True)}" '
                        f'target="_blank" rel="noopener">htm</a>'
                    )
        if not links:
            return '<span class="inc-audit-muted">—</span>'

    return '<span class="inc-audit-btn-row">' + "".join(links) + "</span>"


def tool_cell(
    tool_meta: dict | None,
    *,
    tool: str = "",
    report_root: Path | None = None,
) -> str:
    if not tool_meta:
        return '<span class="inc-audit-muted">—</span>'
    finished = tool_meta.get("finished") or tool_meta.get("finished_display") or ""
    status = (tool_meta.get("status") or "").lower()
    output = tool_meta.get("output") or tool_meta.get("output_rel") or ""
    if status == "running":
        return '<span class="inc-audit-running">Running…</span>'
    if not finished and not output:
        return '<span class="inc-audit-muted">—</span>'

    links: list[str] = []
    if output:
        rel = _pages_href(str(output))
        links.append(
            f'<a class="inc-audit-btn" href="{html.escape(rel, quote=True)}" '
            f'target="_blank" rel="noopener">txt</a>'
        )
        # Nikto HTML report lives next to output.txt as nikto.htm
        if tool == "nikto":
            htm_rel_root = str(Path(str(output)).with_name("nikto.htm")).replace("\\", "/")
            htm_disk = (
                (report_root / str(output).lstrip("/")).with_name("nikto.htm")
                if report_root is not None
                else None
            )
            if htm_disk is None or htm_disk.is_file():
                htm_href = _pages_href(htm_rel_root)
                links.append(
                    f'<a class="inc-audit-btn" href="{html.escape(htm_href, quote=True)}" '
                    f'target="_blank" rel="noopener">htm</a>'
                )
        # ffuf: open each finding URL in Firefox (discover-ffuf: protocol)
        if tool == "ffuf" and report_root is not None:
            json_rel = str(Path(str(output)).with_name("ffuf.json")).replace("\\", "/")
            json_disk = report_root / json_rel.lstrip("/")
            if json_disk.is_file():
                # Absolute path so the desktop handler can open the JSON reliably
                abs_json = str(json_disk.resolve())
                href = "discover-ffuf:" + quote(abs_json, safe="/:")
                links.append(
                    f'<a class="inc-audit-btn" href="{html.escape(href, quote=True)}" '
                    f'title="Open each ffuf finding URL in Firefox">'
                    f"url</a>"
                )

    btn_block = (
        '<span class="inc-audit-btn-row">' + "".join(links) + "</span>" if links else ""
    )
    time_html = html.escape(str(finished)) if finished else ""

    if time_html and btn_block:
        # Flex row vertically centers timestamp with TXT/HTM (gap ~ four spaces).
        return (
            '<span class="inc-audit-tool-cell">'
            f'<span class="inc-audit-tool-cell-time">{time_html}</span>'
            f"{btn_block}"
            "</span>"
        )
    if btn_block:
        return btn_block
    if time_html:
        return time_html
    return '<span class="inc-audit-muted">—</span>'


def build_html(report_root: Path) -> str:
    mode = load_json(report_root / "assets" / "report-mode.json", {})
    mode_name = (mode.get("mode") or "operator").lower()

    audit_rows = load_audit_lines(report_root)
    host_rows = load_host_scan_summary(report_root)
    scan_output_index = build_host_scan_output_index(report_root)
    exports = load_exports(report_root)

    lines: list[str] = []

    if mode_name == "client":
        lines.append(
            '<p class="inc-audit-note">This is a read-only client package. '
            "Tool launches are disabled. Outputs below were produced during the assessment.</p>"
        )
    elif mode_name == "defender":
        lines.append(
            '<p class="inc-audit-note">Defender package: operator egress IPs may be included in the audit log. '
            "Tool launches are disabled.</p>"
        )

    # Target scans
    lines.append('<section class="inc-audit-section">')
    lines.append('<h3 class="inc-audit-section-title">Target scans</h3>')
    lines.append(
        '<div class="inc-content-frame inc-content-frame--table inc-audit-frame-wide">'
    )
    lines.append(
        '<table class="table table-bordered inc-data-table inc-audit-host-scans">'
    )
    tool_headers = "".join(
        f'<th scope="col" class="inc-sortable">{html.escape(label)}</th>'
        for _key, label in HOST_SCAN_TOOLS
    )
    lines.append(
        "<thead><tr>"
        '<th scope="col" class="inc-sortable">Target</th>'
        f"{tool_headers}"
        "</tr></thead><tbody>"
    )
    if host_rows:
        for row in host_rows:
            tools = row.get("tools") or {}
            cells = []
            for key, _label in HOST_SCAN_TOOLS:
                meta = tools.get(key)
                cells.append(
                    tool_cell(
                        meta if isinstance(meta, dict) else None,
                        tool=key,
                        report_root=report_root,
                    )
                )
            lines.append(
                "<tr>"
                f"<td>{html.escape(row['host'])}</td>"
                + "".join(f"<td>{c}</td>" for c in cells)
                + "</tr>"
            )
    else:
        lines.append(
            '<tr><td colspan="5" class="inc-audit-muted inc-audit-empty">No host scans recorded yet.</td></tr>'
        )
    lines.append("</tbody></table></div></section>")

    # Audit log
    lines.append('<section class="inc-audit-section inc-audit-section--log">')
    lines.append('<h3 class="inc-audit-section-title">Audit log</h3>')
    lines.append(
        '<div class="inc-content-frame inc-content-frame--table inc-audit-frame-wide">'
    )
    lines.append(
        '<table class="table table-bordered inc-data-table" id="inc-audit-log-table" '
        'data-default-col="0" data-default-dir="-1">'
    )
    lines.append(
        "<thead><tr>"
        '<th scope="col" class="inc-sortable inc-audit-col-time">Time (UTC)</th>'
        '<th scope="col" class="inc-sortable inc-audit-col-op">Operator</th>'
        '<th scope="col" class="inc-sortable inc-audit-col-ip">Operator IP</th>'
        '<th scope="col" class="inc-sortable inc-audit-col-target">Target</th>'
        '<th scope="col" class="inc-sortable inc-audit-col-action">Action</th>'
        '<th scope="col" class="inc-audit-col-trail">Output</th>'
        "</tr></thead><tbody>"
    )
    if audit_rows:
        for ts, operator, ip, action in audit_rows:
            # Parse Target/Output from full action; show shortened Action text.
            out_cell = audit_output_cell(action, report_root, scan_output_index)
            op_disp = operator if operator else "—"
            target = audit_target_from_action(action)
            target_disp = target if target else "—"
            action_disp = _display_audit_action(
                action,
                report_root=report_root,
                scan_index=scan_output_index,
                ts=ts,
            )
            lines.append(
                "<tr>"
                f'<td class="inc-audit-col-time">{html.escape(ts)}</td>'
                f'<td class="inc-audit-col-op">{html.escape(op_disp)}</td>'
                f'<td class="inc-audit-col-ip">{html.escape(ip)}</td>'
                f'<td class="inc-audit-col-target">{html.escape(target_disp)}</td>'
                f'<td class="inc-audit-col-action">{html.escape(action_disp)}</td>'
                f'<td class="inc-audit-col-trail">{out_cell}</td>'
                "</tr>"
            )
    else:
        lines.append(
            '<tr><td colspan="6" class="inc-audit-muted">No audit events yet.</td></tr>'
        )
    lines.append("</tbody></table></div></section>")

    # Exports (bottom)
    lines.append('<section class="inc-audit-section inc-audit-section--deliverables">')
    lines.append('<h3 class="inc-audit-section-title">Exports</h3>')
    lines.append(
        '<div class="inc-content-frame inc-content-frame--table inc-audit-frame-wide">'
    )
    lines.append(
        '<table class="table table-bordered inc-data-table inc-audit-deliverables">'
    )
    lines.append(
        "<thead><tr>"
        '<th scope="col" class="inc-sortable">Label</th>'
        '<th scope="col" class="inc-sortable">Kind</th>'
        '<th scope="col" class="inc-sortable">Exported (UTC)</th>'
        '<th scope="col" class="inc-sortable">Operator IPs</th>'
        '<th scope="col" class="inc-audit-col-file">File</th>'
        "</tr></thead><tbody>"
    )
    if exports:
        for exp in exports:
            label = format_export_label(str(exp.get("label") or ""))
            kind = format_export_kind(str(exp.get("kind") or "client"))
            exported = format_export_time(exp)
            ips = "Included" if exp.get("include_operator_ips") else "Redacted"
            archive = exp.get("archive") or ""
            arch_cell = html.escape(os.path.basename(archive)) if archive else "—"
            lines.append(
                "<tr>"
                f"<td>{html.escape(label)}</td>"
                f"<td>{html.escape(kind)}</td>"
                f"<td>{html.escape(exported)}</td>"
                f"<td>{html.escape(ips)}</td>"
                f'<td class="inc-audit-col-file">{arch_cell}</td>'
                "</tr>"
            )
    else:
        lines.append(
            '<tr><td colspan="5" class="inc-audit-muted inc-audit-empty">No exports recorded yet.</td></tr>'
        )
    lines.append("</tbody></table></div></section>")

    return "\n".join(lines)


def write_audit_page(report_root: Path, template_path: Path | None = None) -> Path:
    report_root = report_root.resolve()
    page_path = report_root / "pages" / "audit.htm"
    content = build_html(report_root)

    template = ""
    if template_path and template_path.is_file():
        template = template_path.read_text(encoding="utf-8")
    elif page_path.is_file() and "#AUDIT_CONTENT#" in page_path.read_text(encoding="utf-8", errors="replace"):
        template = page_path.read_text(encoding="utf-8")
    else:
        discover = Path(__file__).resolve().parent.parent
        candidate = discover / "report" / "pages" / "audit.htm"
        if candidate.is_file():
            template = candidate.read_text(encoding="utf-8")

    if not template or "#AUDIT_CONTENT#" not in template:
        template = (
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
            "<title>Audit</title></head><body class=\"inc-audit-page\">"
            "<h1>Audit</h1>\n#AUDIT_CONTENT#\n</body></html>\n"
        )

    page_path.parent.mkdir(parents=True, exist_ok=True)
    page_path.write_text(template.replace("#AUDIT_CONTENT#", content), encoding="utf-8")
    return page_path


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("Usage: audit-build.py <report_root> [template_audit.htm]", file=sys.stderr)
        return 2
    report_root = Path(argv[1])
    template = Path(argv[2]) if len(argv) > 2 else None
    if template is None:
        # Discover layout: script is recon/audit-build.py → report/pages/audit.htm
        discover = Path(__file__).resolve().parent.parent
        candidate = discover / "report" / "pages" / "audit.htm"
        if candidate.is_file():
            template = candidate
    path = write_audit_page(report_root, template)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
