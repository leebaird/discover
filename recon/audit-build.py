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

LINE_RE = re.compile(
    r"^(\d{2}-\d{2}-\d{4} Z - \d{2}:\d{2}) \| ([^|]+) \| (.*)$"
)

# Host-scan tools: storage key → display label (alphabetical by key).
HOST_SCAN_TOOLS: list[tuple[str, str]] = [
    ("ffuf", "ffuf"),
    ("nikto", "Nikto"),
    ("nuclei", "Nuclei"),
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
    """Skip routine noise (e.g. Import report open) on the Audit page."""
    a = (action or "").strip().rstrip(".").lower()
    return a.startswith("opened report in discover")


def load_audit_lines(report_root: Path) -> list[tuple[str, str, str]]:
    log = report_root / "tools" / "audit" / "log.txt"
    if not log.is_file():
        return []
    rows = []
    for raw in log.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        m = LINE_RE.match(raw)
        if m:
            action = m.group(3).strip()
            if _audit_action_hidden(action):
                continue
            rows.append((m.group(1), m.group(2).strip(), action))
        else:
            if _audit_action_hidden(raw):
                continue
            rows.append(("", "", raw))
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

    chunks: list[str] = []
    if finished:
        chunks.append(html.escape(str(finished)))

    links: list[str] = []
    if output:
        rel = _pages_href(str(output))
        links.append(
            f'<a class="inc-audit-btn" href="{html.escape(rel, quote=True)}" '
            f'target="_blank" rel="noopener">scan</a>'
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

    if links:
        # Buttons on the same line as the timestamp
        btn_block = '<span class="inc-audit-btn-row">' + "".join(links) + "</span>"
        chunks.append(btn_block)

    return " · ".join(chunks) if chunks else '<span class="inc-audit-muted">—</span>'


def build_html(report_root: Path) -> str:
    mode = load_json(report_root / "assets" / "report-mode.json", {})
    mode_name = (mode.get("mode") or "operator").lower()

    audit_rows = load_audit_lines(report_root)
    host_rows = load_host_scan_summary(report_root)
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

    # Host scan activity
    lines.append('<section class="inc-audit-section">')
    lines.append('<h3 class="inc-audit-section-title">Host scan activity</h3>')
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
            '<tr><td colspan="4" class="inc-audit-muted inc-audit-empty">No host scans recorded yet.</td></tr>'
        )
    lines.append("</tbody></table></div></section>")

    # Deliverables
    lines.append('<section class="inc-audit-section inc-audit-section--deliverables">')
    lines.append('<h3 class="inc-audit-section-title">Deliverables</h3>')
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

    # Audit log
    lines.append('<section class="inc-audit-section inc-audit-section--log">')
    lines.append('<h3 class="inc-audit-section-title">Audit log</h3>')
    lines.append(
        '<div class="inc-content-frame inc-content-frame--table inc-audit-frame-wide">'
    )
    lines.append(
        '<table class="table table-bordered inc-data-table" id="inc-audit-log-table">'
    )
    lines.append(
        "<thead><tr>"
        '<th scope="col" class="inc-sortable">Time (UTC)</th>'
        '<th scope="col" class="inc-sortable">Operator IP</th>'
        '<th scope="col" class="inc-sortable">Action</th>'
        "</tr></thead><tbody>"
    )
    if audit_rows:
        for ts, ip, action in audit_rows:
            lines.append(
                "<tr>"
                f"<td>{html.escape(ts)}</td>"
                f"<td>{html.escape(ip)}</td>"
                f"<td>{html.escape(action)}</td>"
                "</tr>"
            )
    else:
        lines.append(
            '<tr><td colspan="3" class="inc-audit-muted">No audit events yet.</td></tr>'
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
