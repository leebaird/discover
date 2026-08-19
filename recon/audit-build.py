#!/usr/bin/env python3
# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
"""Build Audit page HTML for a Discover engagement report."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import quote, urlparse

# Display stamp: "mm/dd/yyyy - hh:mm Z" (current); dash-date and legacy "Z - hh:mm" still parse
_AUDIT_TS = r"(\d{2}[-/]\d{2}[-/]\d{4}(?: - \d{2}:\d{2} Z| Z - \d{2}:\d{2}))"
# Current: time | operator | ip | action
LINE_RE4 = re.compile(rf"^{_AUDIT_TS} \| ([^|]+) \| ([^|]+) \| (.*)$")
# Legacy: time | ip | action
LINE_RE3 = re.compile(rf"^{_AUDIT_TS} \| ([^|]+) \| (.*)$")

# Host-scan tools: storage key → display label (quietest → loudest).
# droopescan / wpscan are gated on the Subdomains panel (CMS / WordPress)
# but always appear as Target scans columns so prior runs remain visible.
HOST_SCAN_TOOLS: list[tuple[str, str]] = [
    ("nuclei", "Nuclei"),
    ("droopescan", "droopescan"),
    ("wpscan", "WPScan"),
    ("robots", "robots"),
    ("nikto", "Nikto"),
    ("feroxbuster", "feroxbuster"),
    ("ffuf", "ffuf"),
]

# Known export kinds / common labels → display text on the Audit page.
EXPORT_KIND_DISPLAY = {
    "client": "Client",
    "defender": "Defender",
    "defenders": "Defenders",
    "audit-only": "Defender",  # legacy kind name
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


def _is_audit_display_ts(s: str) -> bool:
    """True if s is mm/dd/yyyy - hh:mm Z (or dash-date / legacy Z - hh:mm)."""
    return bool(
        re.fullmatch(
            r"\d{2}[-/]\d{2}[-/]\d{4}(?: - \d{2}:\d{2} Z| Z - \d{2}:\d{2})",
            (s or "").strip(),
        )
    )


def normalize_audit_display_ts(s: str) -> str:
    """Canonical display stamp: mm/dd/yyyy - hh:mm Z (fix legacy Z - hh:mm)."""
    text = (s or "").strip()
    m = re.fullmatch(
        r"(\d{2})[-/](\d{2})[-/](\d{4})\s+Z\s+-\s+(\d{2}:\d{2})",
        text,
    )
    if m:
        return f"{m.group(1)}/{m.group(2)}/{m.group(3)} - {m.group(4)} Z"
    m2 = re.fullmatch(
        r"(\d{2})[-/](\d{2})[-/](\d{4})\s+-\s+(\d{2}:\d{2})\s+Z",
        text,
    )
    if m2:
        return f"{m2.group(1)}/{m2.group(2)}/{m2.group(3)} - {m2.group(4)} Z"
    return text


def format_export_time(exp: dict) -> str:
    """Match audit log times: mm/dd/yyyy - hh:mm Z (UTC)."""
    display = (exp.get("exported_at_display") or "").strip()
    if display and _is_audit_display_ts(display):
        return normalize_audit_display_ts(display)

    raw = (exp.get("exported_at_utc") or display or "").strip()
    if not raw:
        return "—"

    # Already audit-log style (current, dash-date, or legacy)
    if _is_audit_display_ts(raw):
        return normalize_audit_display_ts(raw)

    # ISO-8601 UTC: 2026-07-16T00:37:51Z or with offset
    try:
        from datetime import datetime, timezone

        cleaned = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%m/%d/%Y - %H:%M Z")
    except Exception:
        return raw


def _audit_action_hidden(action: str) -> bool:
    """Skip routine noise on the Audit page (action field or full raw line)."""
    a = (action or "").strip().rstrip(".").lower()
    # Import / reopen noise — never show on Audit log.
    if a.startswith("opened report in discover") or "opened report in discover" in a:
        return True
    # Exports are listed in the Exports table; omit from the audit log.
    if a.startswith("exported ") or " | exported " in a:
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
    if not host or tool not in {"ffuf", "feroxbuster", "nikto", "nuclei", "droopescan", "wpscan", "robots"}:
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


def _format_scan_duration(seconds: float | int) -> str:
    """Human duration for Finished rows: '5 min 14 sec', '45 sec', '2 min'."""
    try:
        total = int(round(float(seconds)))
    except (TypeError, ValueError):
        return ""
    if total < 0:
        total = 0
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    parts: list[str] = []
    if hours:
        parts.append(f"{hours} hr")
    if minutes:
        parts.append(f"{minutes} min")
    if secs or not parts:
        parts.append(f"{secs} sec")
    return " ".join(parts)


def _parse_meta_utc(raw: str):
    """Parse meta started_utc / finished_utc → aware UTC datetime or None."""
    from datetime import datetime, timezone

    text = (raw or "").strip()
    if not text:
        return None
    try:
        cleaned = text.replace("Z", "+00:00") if text.endswith("Z") else text
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _duration_for_finished_scan(
    report_root: Path,
    host: str,
    tool: str,
    audit_ts: str,
    scan_index: dict[str, dict[str, dict]],
) -> str:
    """Duration string from meta.json started_utc/finished_utc for this finish event."""
    host = (host or "").lower()
    tool = (tool or "").lower()
    if tool.startswith("nuclei pass"):
        tool = "nuclei"
    if not host or tool not in {"ffuf", "feroxbuster", "nikto", "nuclei", "droopescan", "wpscan", "robots"}:
        return ""

    audit_ts = (audit_ts or "").strip()
    base = report_root / "tools" / "host-scans" / host / tool
    metas: list[dict] = []

    if base.is_dir():
        for run_dir in sorted(base.iterdir(), reverse=True):
            if not run_dir.is_dir():
                continue
            meta_path = run_dir / "meta.json"
            if meta_path.is_file():
                meta = load_json(meta_path, {})
                if isinstance(meta, dict) and meta:
                    metas.append(meta)

    # latest.json may lack started_utc; still try sibling meta via output path
    meta_latest = (scan_index.get(host) or {}).get(tool) or {}
    rel = str(meta_latest.get("output") or meta_latest.get("output_rel") or "").strip()
    if rel:
        meta_path = (report_root / rel.lstrip("/")).with_name("meta.json")
        if meta_path.is_file():
            meta = load_json(meta_path, {})
            if isinstance(meta, dict) and meta and meta not in metas:
                metas.insert(0, meta)

    def duration_from_meta(meta: dict) -> str:
        start = _parse_meta_utc(str(meta.get("started_utc") or ""))
        end = _parse_meta_utc(str(meta.get("finished_utc") or ""))
        if not start or not end:
            return ""
        return _format_scan_duration((end - start).total_seconds())

    # Prefer meta whose finished_display matches the audit finish time.
    for meta in metas:
        fin_disp = str(meta.get("finished_display") or meta.get("finished") or "").strip()
        if audit_ts and fin_disp == audit_ts:
            dur = duration_from_meta(meta)
            if dur:
                return dur

    # Fall back to newest meta with both timestamps.
    for meta in metas:
        dur = duration_from_meta(meta)
        if dur:
            return dur
    return ""


def _display_audit_action(
    action: str,
    *,
    report_root: Path | None = None,
    scan_index: dict[str, dict[str, dict]] | None = None,
    ts: str = "",
) -> str:
    """Action column: Started → exact Command; Finished → tool + duration."""
    text = _normalize_audit_action(action)
    if not text:
        return text

    m = re.match(
        r"(?i)^(started|finished)\s+"
        r"(nuclei(?:\s+pass-2)?|droopescan|wpscan|robots|feroxbuster|ffuf|nikto)\b",
        text,
    )
    if m:
        verb = m.group(1).lower()
        tool_raw = re.sub(r"\s+", " ", m.group(2).strip().lower())
        scan_m = _AUDIT_SCAN_ACTION_RE.search(action or "")
        host = ""
        if scan_m:
            host = _hostname_from_url(scan_m.group("url").rstrip(".,;"))
        tool = "nuclei" if tool_raw.startswith("nuclei") else tool_raw

        if verb == "started" and report_root is not None:
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

        # Finished … in N min M sec. (keep non-zero exit)
        exit_m = re.search(r"\(exit\s+(\d+)\)", text, re.I)
        exit_note = ""
        if exit_m and exit_m.group(1) != "0":
            exit_note = f" (exit {exit_m.group(1)})"

        duration = ""
        if report_root is not None:
            duration = _duration_for_finished_scan(
                report_root,
                host,
                tool,
                ts,
                scan_index or {},
            )
        if duration:
            return f"Finished {tool_raw} in {duration}{exit_note}."
        return f"Finished {tool_raw}{exit_note}."

    # Ran Shodan enrichment (long stats…). → Ran Shodan enrichment.
    if re.match(r"(?i)^ran shodan enrichment\b", text):
        return "Ran Shodan enrichment."

    if text.endswith("."):
        return text
    return text + "."


def _is_finished_host_scan_action(action: str) -> bool:
    """Finished nuclei/nikto/ffuf/… — Action shows tool + duration; no IP/Target."""
    text = _normalize_audit_action(action)
    return bool(
        re.match(
            r"(?i)^finished\s+"
            r"(nuclei(?:\s+pass-2)?|droopescan|wpscan|robots|feroxbuster|ffuf|nikto)\b",
            text,
        )
    )


def _audit_action_hides_operator_ip(action: str) -> bool:
    """Actions that must not show operator egress IP on the Audit page."""
    a = (action or "").strip().lower()
    if "shodan" in a:
        return True
    # Active Update → Software CVEs / NVD refresh
    if "software cve" in a or "updated software cve" in a:
        return True
    # Import subdomains (existing sources or CSV list)
    if a.startswith("imported subdomains") or a.startswith("imported csv list subdomains"):
        return True
    # Import names / names+titles+emails
    if a.startswith("imported names"):
        return True
    # Audit page → Import operator package
    if a.startswith("imported operator package"):
        return True
    # Finished host-scan: duration is in Action; IP not needed on the row
    if _is_finished_host_scan_action(action):
        return True
    return False


def _display_operator_ip(ip: str, action: str) -> str:
    """Operator IP column; hide egress for selected recon actions (em dash)."""
    if _audit_action_hides_operator_ip(action):
        return "—"
    text = (ip or "").strip()
    return text if text else "—"


def _display_audit_target(action: str) -> str:
    """Target column; hide for Finished host-scan rows (duration is in Action)."""
    if _is_finished_host_scan_action(action):
        return "—"
    target = audit_target_from_action(action)
    return target if target else "—"


def audit_line_hash(raw_line: str) -> str:
    """Stable id for one on-disk audit log line (stripped)."""
    return hashlib.sha256(raw_line.strip().encode("utf-8")).hexdigest()


def load_audit_lines(
    report_root: Path,
) -> list[tuple[str, str, str, str, str]]:
    """Return (time, operator, ip, action, raw_line). Legacy 3-field: empty operator."""
    log = report_root / "tools" / "audit" / "log.txt"
    if not log.is_file():
        return []
    rows: list[tuple[str, str, str, str, str]] = []
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
                    raw,
                )
            )
            continue
        m3 = LINE_RE3.match(raw)
        if m3:
            action = _normalize_audit_action(m3.group(3).strip())
            if _audit_action_hidden(action):
                continue
            # Legacy: second field is IP (no operator name).
            rows.append((m3.group(1), "", m3.group(2).strip(), action, raw))
        else:
            if _audit_action_hidden(raw):
                continue
            rows.append(("", "", "", _normalize_audit_action(raw), raw))
    rows.reverse()  # newest first
    return rows


def delete_audit_line_by_hash(report_root: Path, line_hash: str) -> dict:
    """Remove one log.txt line whose SHA-256 matches line_hash; rebuild Audit.

    Returns a JSON-serializable dict with ok / error / summary.
    """
    report_root = Path(report_root).resolve()
    want = (line_hash or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", want):
        return {"ok": False, "error": "Invalid line id."}

    log = report_root / "tools" / "audit" / "log.txt"
    if not log.is_file():
        return {"ok": False, "error": "Audit log not found."}

    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"ok": False, "error": f"Could not read audit log: {exc}"}

    out: list[str] = []
    found = False
    removed_preview = ""
    for line in text.splitlines(keepends=True):
        raw = line.rstrip("\n\r")
        stripped = raw.strip()
        if (
            not found
            and stripped
            and not stripped.startswith("#")
            and audit_line_hash(stripped) == want
        ):
            found = True
            removed_preview = stripped
            continue
        out.append(line)

    if not found:
        return {"ok": False, "error": "Audit line not found (already deleted?)."}

    new_text = "".join(out)
    try:
        log.write_text(new_text, encoding="utf-8")
    except OSError as exc:
        return {"ok": False, "error": f"Could not write audit log: {exc}"}

    discover = Path(__file__).resolve().parent.parent
    template = discover / "report" / "pages" / "audit.htm"
    try:
        write_audit_page(report_root, template if template.is_file() else None)
    except Exception as exc:
        return {
            "ok": False,
            "error": f"Line removed but Audit page rebuild failed: {exc}",
        }

    # Short preview for UI (time | action tail).
    preview = removed_preview
    m4 = LINE_RE4.match(removed_preview)
    if m4:
        preview = f"{m4.group(1)} | {m4.group(4).strip()}"
    elif LINE_RE3.match(removed_preview):
        m3 = LINE_RE3.match(removed_preview)
        if m3:
            preview = f"{m3.group(1)} | {m3.group(3).strip()}"
    if len(preview) > 160:
        preview = preview[:157] + "."

    return {
        "ok": True,
        "summary": "Audit line deleted.",
        "preview": preview,
        "hash": want,
    }


def _newest_host_scan_tool_meta(tool_dir: Path) -> dict:
    """Pick the newest run meta under host/tool/ (stamp dirs). Prefer finished over running."""
    best: dict | None = None
    best_key: tuple = ("", -1)
    if not tool_dir.is_dir():
        return {}
    for run_dir in tool_dir.iterdir():
        if not run_dir.is_dir():
            continue
        meta_path = run_dir / "meta.json"
        if not meta_path.is_file():
            continue
        meta = load_json(meta_path, {})
        if not isinstance(meta, dict) or not meta:
            continue
        st = str(meta.get("status") or "").strip().lower() or "done"
        rank = 0 if st == "running" else 1
        key = (run_dir.name, rank)
        if best is None or key >= best_key:
            best_key = key
            out = str(meta.get("output") or meta.get("output_rel") or "").strip()
            if not out:
                out = f"tools/host-scans/{tool_dir.parent.name}/{tool_dir.name}/{run_dir.name}/output.txt"
            finished = str(
                meta.get("finished_display") or meta.get("finished") or ""
            ).strip()
            best = {
                "status": st,
                "finished": finished,
                "finished_display": finished,
                "output": out,
                "output_rel": out,
                "software": meta.get("software") or "",
                "url": meta.get("url") or "",
            }
            if meta.get("skip_reason"):
                best["skip_reason"] = meta.get("skip_reason")
            if meta.get("disallow_count") is not None:
                best["disallow_count"] = meta.get("disallow_count")
            if meta.get("url_count") is not None:
                best["url_count"] = meta.get("url_count")
            elif tool_dir.name in {"ffuf", "feroxbuster"}:
                json_name = "ffuf.json" if tool_dir.name == "ffuf" else "ferox.json"
                json_disk = run_dir / json_name
                best["url_count"] = _host_scan_finding_url_count(json_disk)
    return best or {}


def _reconcile_tool_meta(report_root: Path, host: str, tool: str, meta: dict) -> dict:
    """If status.json says running but a newer finished run exists, use the finished one."""
    if not isinstance(meta, dict):
        meta = {}
    tool_dir = report_root / "tools" / "host-scans" / host / tool
    newest = _newest_host_scan_tool_meta(tool_dir)
    if not newest:
        return meta
    st = str(meta.get("status") or "").lower()
    if st == "running" or not meta:
        # Prefer newest finished (or newest anything if still running).
        return newest
    # status.json may lag behind a finished re-run
    out_old = str(meta.get("output") or "")
    out_new = str(newest.get("output") or "")
    if out_new and out_new != out_old and newest.get("status") != "running":
        # Compare stamps from paths when possible
        def stamp_from_out(path: str) -> str:
            parts = Path(path).parts
            # tools/host-scans/host/tool/stamp/output.txt
            if len(parts) >= 2:
                return parts[-2]
            return ""

        if stamp_from_out(out_new) >= stamp_from_out(out_old):
            return newest
    return meta


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
            fixed: dict[str, dict] = {}
            for tool, meta in tools.items():
                if not isinstance(meta, dict):
                    continue
                fixed[tool] = _reconcile_tool_meta(
                    report_root, str(host).lower(), str(tool).lower(), meta
                )
            rows.append(
                {
                    "host": host,
                    "tools": fixed,
                }
            )
        rows.sort(key=lambda r: r["host"])
        return rows

    # Fallback: walk directories (newest meta per tool)
    rows = []
    for host_dir in sorted(base.iterdir()):
        if not host_dir.is_dir() or host_dir.name.startswith("."):
            continue
        tools = {}
        for tool, _label in HOST_SCAN_TOOLS:
            newest = _newest_host_scan_tool_meta(host_dir / tool)
            if newest:
                tools[tool] = newest
            else:
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
    r"(?P<tool>nuclei\s+pass-2|droopescan|wpscan|robots|feroxbuster|ffuf|nikto|nuclei)\b"
    r".*?\bon\s+(?P<url>https?://[^\s)(]+)"
)


def _hostname_from_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _host_scan_finding_url_count(json_disk: Path) -> int:
    """Unique HTTP(S) finding URLs in ffuf.json or ferox.json (not config/stats)."""
    if not json_disk.is_file():
        return 0
    try:
        text = json_disk.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    seen: set[str] = set()

    def add(url: object) -> None:
        u = str(url or "").strip()
        if u.startswith(("http://", "https://")):
            seen.add(u)

    data = None
    try:
        data = json.loads(text)
    except Exception:
        data = None
    if isinstance(data, dict):
        for row in data.get("results") or []:
            if isinstance(row, dict):
                add(row.get("url"))
    elif isinstance(data, list):
        for row in data:
            if isinstance(row, dict) and row.get("type") in (None, "response"):
                add(row.get("url") or row.get("original_url"))

    # feroxbuster --json is NDJSON (configuration / response / statistics).
    if not seen or data is None:
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
    return len(seen)


def audit_target_from_action(action: str) -> str:
    """Host/target for audit log Target column (host scans; batch Active → Multiple)."""
    text = (action or "").strip()
    # Import-batch Active probes many hosts — not a single Target cell.
    if re.search(r"(?i)ran active recon on imported hosts\b", text):
        return "Multiple"
    m = _AUDIT_SCAN_ACTION_RE.search(text)
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
    """Output column: scan / htm / pass2 buttons when the action is a host scan.

    Icons appear on the Started line only. Finished rows already share the same
    report via the prior scan line, so they show a muted dash.
    """
    m = _AUDIT_SCAN_ACTION_RE.search(action or "")
    if not m:
        return '<span class="inc-audit-muted">—</span>'

    # Finished … already linked from the Started row for that scan.
    if m.group("verb").lower() == "finished":
        return '<span class="inc-audit-muted">—</span>'

    tool_raw = re.sub(r"\s+", " ", m.group("tool").strip().lower())
    url = m.group("url").rstrip(".,;")
    host = _hostname_from_url(url)
    if not host:
        return '<span class="inc-audit-muted">—</span>'

    is_pass2 = tool_raw.startswith("nuclei pass-2") or tool_raw == "nuclei pass-2"
    tool = "nuclei" if is_pass2 or tool_raw == "nuclei" else tool_raw
    if tool not in {"ffuf", "feroxbuster", "nikto", "nuclei", "droopescan", "wpscan", "robots"}:
        return '<span class="inc-audit-muted">—</span>'

    meta = (scan_index.get(host) or {}).get(tool) or {}
    output = str(meta.get("output") or meta.get("output_rel") or "").strip()
    status = (meta.get("status") or "").lower()

    # Do not leave Output stuck on "Running." for abandoned mid-runs (imported
    # packages / killed scans). Prefer txt/htm when files exist; else muted dash.
    # Live progress is shown on Subdomains expand, not the static Audit log.
    if status == "running" and not is_pass2:
        if not output:
            return '<span class="inc-audit-muted">—</span>'
        # Fall through to link buttons when output path is known.

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
            txt_rel = output
            # robots: prefer raw robots.txt body for the green txt button
            if tool == "robots":
                robots_rel = str(Path(output).with_name("robots.txt")).replace("\\", "/")
                robots_disk = report_root / robots_rel.lstrip("/")
                if robots_disk.is_file():
                    txt_rel = robots_rel
            href = _pages_href(txt_rel)
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
            if tool == "robots":
                list_rel = str(Path(output).with_name("disallow-urls.txt")).replace(
                    "\\", "/"
                )
                list_disk = report_root / list_rel.lstrip("/")
                if list_disk.is_file() and list_disk.stat().st_size > 0:
                    abs_list = str(list_disk.resolve())
                    robots_href = "discover-robots:" + quote(abs_list, safe="/:")
                    links.append(
                        f'<a class="inc-audit-btn" href="{html.escape(robots_href, quote=True)}" '
                        f'title="Open each robots.txt Disallow directory in Firefox">'
                        f"htm</a>"
                    )
            # ffuf: open each finding URL in Firefox (same as Target scans / expand).
            if tool == "ffuf":
                json_rel = str(Path(output).with_name("ffuf.json")).replace("\\", "/")
                json_disk = report_root / json_rel.lstrip("/")
                if json_disk.is_file() and _host_scan_finding_url_count(json_disk) > 0:
                    abs_json = str(json_disk.resolve())
                    ffuf_href = "discover-ffuf:" + quote(abs_json, safe="/:")
                    links.append(
                        f'<a class="inc-audit-btn" href="{html.escape(ffuf_href, quote=True)}" '
                        f'title="Open each ffuf finding URL in Firefox">'
                        f"url</a>"
                    )
            if tool == "feroxbuster":
                json_rel = str(Path(output).with_name("ferox.json")).replace("\\", "/")
                json_disk = report_root / json_rel.lstrip("/")
                if json_disk.is_file() and _host_scan_finding_url_count(json_disk) > 0:
                    abs_json = str(json_disk.resolve())
                    ferox_href = "discover-ferox:" + quote(abs_json, safe="/:")
                    links.append(
                        f'<a class="inc-audit-btn" href="{html.escape(ferox_href, quote=True)}" '
                        f'title="Open each feroxbuster finding URL in Firefox">'
                        f"url</a>"
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
    finished = normalize_audit_display_ts(
        str(tool_meta.get("finished") or tool_meta.get("finished_display") or "")
    )
    status = (tool_meta.get("status") or "").lower()
    output = tool_meta.get("output") or tool_meta.get("output_rel") or ""
    # Target scans: no live "Running." label — muted dash (same as empty).
    if status == "running":
        return '<span class="inc-audit-muted">—</span>'
    if not finished and not output:
        return '<span class="inc-audit-muted">—</span>'

    links: list[str] = []
    if output:
        txt_path = str(output)
        # robots: green txt opens the raw robots.txt body when present
        if tool == "robots" and report_root is not None:
            robots_rel = str(Path(str(output)).with_name("robots.txt")).replace("\\", "/")
            robots_disk = report_root / robots_rel.lstrip("/")
            if robots_disk.is_file():
                txt_path = robots_rel
        rel = _pages_href(txt_path)
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
        # robots: open each Disallow URL in Firefox (discover-robots: protocol)
        if tool == "robots" and report_root is not None:
            list_rel = str(Path(str(output)).with_name("disallow-urls.txt")).replace(
                "\\", "/"
            )
            list_disk = report_root / list_rel.lstrip("/")
            if list_disk.is_file() and list_disk.stat().st_size > 0:
                abs_list = str(list_disk.resolve())
                href = "discover-robots:" + quote(abs_list, safe="/:")
                links.append(
                    f'<a class="inc-audit-btn" href="{html.escape(href, quote=True)}" '
                    f'title="Open each robots.txt Disallow directory in Firefox">'
                    f"htm</a>"
                )
        # ffuf: open each finding URL in Firefox (discover-ffuf: protocol)
        if tool == "ffuf" and report_root is not None:
            json_rel = str(Path(str(output)).with_name("ffuf.json")).replace("\\", "/")
            json_disk = report_root / json_rel.lstrip("/")
            if json_disk.is_file() and _host_scan_finding_url_count(json_disk) > 0:
                # Absolute path so the desktop handler can open the JSON reliably
                abs_json = str(json_disk.resolve())
                href = "discover-ffuf:" + quote(abs_json, safe="/:")
                links.append(
                    f'<a class="inc-audit-btn" href="{html.escape(href, quote=True)}" '
                    f'title="Open each ffuf finding URL in Firefox">'
                    f"url</a>"
                )
        if tool == "feroxbuster" and report_root is not None:
            json_rel = str(Path(str(output)).with_name("ferox.json")).replace("\\", "/")
            json_disk = report_root / json_rel.lstrip("/")
            if json_disk.is_file() and _host_scan_finding_url_count(json_disk) > 0:
                abs_json = str(json_disk.resolve())
                href = "discover-ferox:" + quote(abs_json, safe="/:")
                links.append(
                    f'<a class="inc-audit-btn" href="{html.escape(href, quote=True)}" '
                    f'title="Open each feroxbuster finding URL in Firefox">'
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


def _parse_audit_ts_utc(ts: str):
    """Parse display stamp → aware UTC datetime, or None."""
    from datetime import datetime, timezone

    text = normalize_audit_display_ts(ts)
    m = re.fullmatch(
        r"(\d{2})[-/](\d{2})[-/](\d{4})\s+-\s+(\d{2}):(\d{2})\s+Z",
        text,
    )
    if not m:
        return None
    mm, dd, yyyy, hh, mi = (int(m.group(i)) for i in range(1, 6))
    try:
        return datetime(yyyy, mm, dd, hh, mi, tzinfo=timezone.utc)
    except ValueError:
        return None


def _software_product_from_action(action: str) -> str:
    m = re.search(r"\(software:\s*([^)]+)\)", action or "", re.I)
    if not m:
        return ""
    label = m.group(1).strip()
    if not label or label in {"-", "—"}:
        return ""
    return re.split(r"[:\[]", label, maxsplit=1)[0].strip()


def _normalize_scan_tool(tool_raw: str) -> str:
    t = re.sub(r"\s+", " ", (tool_raw or "").strip().lower())
    if t.startswith("nuclei"):
        return "nuclei"
    return t


def load_host_categories(report_root: Path) -> dict[str, str]:
    """Map hostname → category from tools/subdomains and tools/private-subs.

    File format: host\\tip[\\tcategory]. Empty/missing category → \"(none)\".
    First non-empty category wins if a host appears more than once.
    """
    mapping: dict[str, str] = {}
    for name in ("subdomains", "private-subs"):
        path = report_root / "tools" / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for raw in text.splitlines():
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            parts = raw.split("\t") if "\t" in raw else raw.split()
            if not parts:
                continue
            host = (parts[0] or "").strip().lower()
            if not host:
                continue
            cat = (parts[2] if len(parts) > 2 else "").strip() or "(none)"
            prev = mapping.get(host)
            # Prefer a real category over (none) when both exist.
            if prev is None or (prev == "(none)" and cat != "(none)"):
                mapping[host] = cat
    return mapping


def _metrics_view_zoneinfo():
    """Operator view timezone for metrics calendar windows (stamps stay UTC)."""
    from datetime import timezone

    try:
        import importlib.util

        path = Path(__file__).resolve().parent / "discover-config.py"
        spec = importlib.util.spec_from_file_location(
            "_discover_config_metrics", path
        )
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod.view_zoneinfo()
    except Exception:
        pass
    return timezone.utc


def _metrics_window_bounds(window: str, now):
    """Return (start_dt|None, end_dt|None exclusive, day_keys|None).

    Calendar windows use the operator view timezone (~/.discover/timezone).
    Written audit stamps stay UTC; bounds are converted for comparison.

      today     — today 00:00 through tomorrow 00:00
      yesterday — yesterday 00:00 through today 00:00
      7d        — last 7 calendar days inclusive of today (start = today-6 00:00)
      week      — previous full calendar week Monday 00:00 through this Monday 00:00
      all       — no lower/upper bound (day_keys filled after events are known)
    """
    from datetime import datetime, timedelta, timezone

    tz = now.tzinfo or timezone.utc
    if now.tzinfo is None:
        now = now.replace(tzinfo=tz)
    else:
        now = now.astimezone(tz)

    today = now.date()

    def midnight(d):
        return datetime(d.year, d.month, d.day, tzinfo=tz)

    if window == "today":
        return midnight(today), midnight(today + timedelta(days=1)), [today]

    if window == "yesterday":
        yday = today - timedelta(days=1)
        return midnight(yday), midnight(today), [yday]

    if window == "week":
        this_monday = today - timedelta(days=today.weekday())
        last_monday = this_monday - timedelta(days=7)
        day_keys = [last_monday + timedelta(days=i) for i in range(7)]
        return midnight(last_monday), midnight(this_monday), day_keys

    if window == "all":
        return None, None, None

    # Default: last 7 calendar days in the view timezone
    start = midnight(today - timedelta(days=6))
    day_keys = [(start.date() + timedelta(days=i)) for i in range(7)]
    return start, None, day_keys


def _dt_in_metrics_window(dt, start, end) -> bool:
    if dt is None:
        return False
    if start is not None and dt < start:
        return False
    if end is not None and dt >= end:
        return False
    return True


def compute_metrics(
    report_root: Path,
    audit_rows: list,
    window: str = "7d",
) -> dict:
    """Aggregate host-scan activity for a metrics window (today | yesterday | 7d | week | all)."""
    from collections import Counter
    from datetime import datetime, timedelta, timezone

    now = datetime.now(_metrics_view_zoneinfo())
    start_bound, end_bound, day_keys = _metrics_window_bounds(window, now)
    day_counts: dict = {}
    if day_keys is not None:
        day_counts = {d: 0 for d in day_keys}

    finished_events: list[tuple] = []  # (dt, operator, tool, host, software) — in window
    started_in_window: list[tuple] = []  # (dt, tool, host)
    # All Finished stamps (any date) for incomplete matching — a run started in the
    # window but finished later must not count as incomplete for that window.
    finished_any: dict[tuple[str, str], list] = {}
    host_cats = load_host_categories(report_root)

    for ts, operator, _ip, action, _raw in audit_rows:
        dt = _parse_audit_ts_utc(ts)
        if dt is None:
            continue
        m = _AUDIT_SCAN_ACTION_RE.search(action or "")
        if not m:
            continue
        verb = m.group("verb").lower()
        tool = _normalize_scan_tool(m.group("tool"))
        if tool not in {"nuclei", "nikto", "ffuf", "feroxbuster", "droopescan", "wpscan", "robots"}:
            continue
        host = _hostname_from_url(m.group("url").rstrip(".,;"))
        if not host:
            continue
        if verb == "finished":
            finished_any.setdefault((tool, host), []).append(dt)
            if not _dt_in_metrics_window(dt, start_bound, end_bound):
                continue
            soft = _software_product_from_action(action)
            finished_events.append((dt, operator or "—", tool, host, soft))
            d = dt.date()
            if day_keys is not None:
                if d in day_counts:
                    day_counts[d] += 1
            else:
                day_counts[d] = day_counts.get(d, 0) + 1
        elif verb == "started":
            if not _dt_in_metrics_window(dt, start_bound, end_bound):
                continue
            started_in_window.append((dt, tool, host))

    for key in finished_any:
        finished_any[key].sort()

    # Incomplete: Started in window with no Finished (any time) for same tool+host at/after start
    incomplete = 0
    for dt, tool, host in started_in_window:
        fins = finished_any.get((tool, host)) or []
        if not any(f >= dt for f in fins):
            incomplete += 1

    by_tool = Counter(t for _d, _o, t, _h, _s in finished_events)
    by_operator = Counter(o for _d, o, _t, _h, _s in finished_events)
    by_software = Counter(
        s for _d, _o, _t, _h, s in finished_events if s
    )
    by_category = Counter(
        host_cats.get(h, "(none)") or "(none)"
        for _d, _o, _t, h, _s in finished_events
    )
    targets = {h for _d, _o, _t, h, _s in finished_events}

    # CVE counts from nuclei pass-2 meta for runs finished in window
    by_cve: Counter = Counter()
    scans_dir = report_root / "tools" / "host-scans"
    if scans_dir.is_dir():
        for meta_path in scans_dir.rglob("meta.json"):
            meta = load_json(meta_path, {})
            if not isinstance(meta, dict):
                continue
            fin = str(meta.get("finished_display") or meta.get("finished") or "").strip()
            fin_dt = _parse_audit_ts_utc(fin) if fin else None
            if fin_dt is None:
                futc = str(meta.get("finished_utc") or "").strip()
                if futc:
                    try:
                        cleaned = futc.replace("Z", "+00:00") if futc.endswith("Z") else futc
                        fin_dt = datetime.fromisoformat(cleaned)
                        if fin_dt.tzinfo is None:
                            fin_dt = fin_dt.replace(tzinfo=timezone.utc)
                        else:
                            fin_dt = fin_dt.astimezone(timezone.utc)
                    except Exception:
                        fin_dt = None
            if not _dt_in_metrics_window(fin_dt, start_bound, end_bound):
                continue
            pass2 = meta.get("pass2") if isinstance(meta.get("pass2"), dict) else {}
            ids = pass2.get("ids") if isinstance(pass2, dict) else None
            if not isinstance(ids, list):
                continue
            for cid in ids:
                c = str(cid or "").strip().upper()
                # Canonical CVE-YYYY-NNNN only (skip template suffixes)
                if re.fullmatch(r"CVE-\d{4}-\d{4,}", c):
                    by_cve[c] += 1

    # "All" day chart: calendar span of activity, capped at 60 days (newest)
    if day_keys is None:
        if day_counts:
            dmax = max(day_counts)
            dmin = min(day_counts)
            if (dmax - dmin).days > 59:
                dmin = dmax - timedelta(days=59)
            day_keys = [dmin + timedelta(days=i) for i in range((dmax - dmin).days + 1)]
        else:
            day_keys = []

    def top_n(counter: Counter, n: int = 10) -> list[tuple[str, int]]:
        return counter.most_common(n)

    return {
        "window": window,
        "targets_scanned": len(targets),
        "scans_completed": len(finished_events),
        "incomplete_scans": incomplete,
        "days": [
            {
                "key": d.isoformat(),
                "label": d.strftime("%m-%d"),
                "count": int(day_counts.get(d, 0)),
            }
            for d in day_keys
        ],
        "by_operator": top_n(by_operator),
        "by_tool": top_n(by_tool),
        "by_cve": top_n(by_cve),
        "by_software": top_n(by_software),
        "by_category": top_n(by_category),
    }


def compute_last7_metrics(report_root: Path, audit_rows: list) -> dict:
    """Backward-compatible alias: last 7 UTC calendar days."""
    return compute_metrics(report_root, audit_rows, "7d")


def _hbar_rows_html(rows: list[tuple[str, int]], empty_label: str = "No data") -> str:
    if not rows:
        return f'<p class="inc-audit-metrics-empty">{html.escape(empty_label)}</p>'
    max_n = max((n for _l, n in rows), default=1) or 1
    parts: list[str] = []
    for label, n in rows:
        pct = max(2, int(round(100.0 * n / max_n))) if n else 0
        parts.append(
            '<div class="inc-audit-metrics-hbar">'
            f'<span class="inc-audit-metrics-hbar-label" title="{html.escape(label)}">'
            f"{html.escape(label)}</span>"
            '<span class="inc-audit-metrics-hbar-track">'
            f'<span class="inc-audit-metrics-hbar-fill" style="width:{pct}%"></span>'
            "</span>"
            f'<span class="inc-audit-metrics-hbar-n">{n}</span>'
            "</div>"
        )
    return "".join(parts)


def _day_bars_html(days: list[dict]) -> str:
    max_n = max((int(d.get("count") or 0) for d in days), default=1) or 1
    parts: list[str] = ['<div class="inc-audit-metrics-bars">']
    for d in days:
        n = int(d.get("count") or 0)
        pct = max(4, int(round(100.0 * n / max_n))) if n else 4
        height = pct if n else 4
        parts.append(
            '<div class="inc-audit-metrics-bar-col">'
            f'<div class="inc-audit-metrics-bar" style="height:{height}%" title="{n}"></div>'
            f'<span>{html.escape(str(d.get("label") or ""))}</span>'
            "</div>"
        )
    parts.append("</div>")
    return "".join(parts)


_METRICS_RANGE_OPTIONS: list[tuple[str, str]] = [
    ("today", "Today"),
    ("yesterday", "Yesterday"),
    ("7d", "Last 7 days"),
    ("week", "Last week"),
    ("all", "All"),
]


def _metrics_range_select_html(selected: str) -> str:
    """Dropdown replacing the old 'Last 7 days' heading."""
    opts: list[str] = []
    for value, label in _METRICS_RANGE_OPTIONS:
        sel = " selected" if value == selected else ""
        opts.append(
            f'<option value="{html.escape(value, quote=True)}"{sel}>'
            f"{html.escape(label)}</option>"
        )
    return (
        '<label class="sr-only" for="inc-audit-metrics-range">Metrics time range</label>'
        '<select id="inc-audit-metrics-range" class="inc-audit-metrics-range" '
        'aria-label="Metrics time range">'
        + "".join(opts)
        + "</select>"
    )


def _render_metrics_panel_body(metrics: dict) -> str:
    """KPI + chart rows for one metrics window (no outer section wrapper)."""
    incomplete_n = int(metrics.get("incomplete_scans") or 0)
    kpi_mod = (
        "inc-audit-metrics-kpis--3" if incomplete_n > 0 else "inc-audit-metrics-kpis--2"
    )
    block_mod = (
        "inc-audit-metrics-kpis-block--3"
        if incomplete_n > 0
        else "inc-audit-metrics-kpis-block--2"
    )
    kpi_html = [
        f'<div class="inc-audit-metrics-kpis-block {block_mod}">',
        f'<div class="inc-audit-metrics-kpis {kpi_mod}">',
        '<div class="inc-audit-metrics-card">',
        '<div class="inc-audit-metrics-card-label">Targets scanned</div>',
        f'<div class="inc-audit-metrics-card-value">{int(metrics.get("targets_scanned") or 0)}</div>',
        "</div>",
        '<div class="inc-audit-metrics-card">',
        '<div class="inc-audit-metrics-card-label">Scans completed</div>',
        f'<div class="inc-audit-metrics-card-value">{int(metrics.get("scans_completed") or 0)}</div>',
        "</div>",
    ]
    if incomplete_n > 0:
        kpi_html.extend(
            [
                '<div class="inc-audit-metrics-card inc-audit-metrics-card--warn">',
                '<div class="inc-audit-metrics-card-label">Incomplete scans</div>',
                f'<div class="inc-audit-metrics-card-value">{incomplete_n}</div>',
                "</div>",
            ]
        )
    kpi_html.append("</div>")  # .inc-audit-metrics-kpis
    kpi_html.append("</div>")  # .inc-audit-metrics-kpis-block

    return "\n".join(
        [
            '<div class="inc-audit-metrics-top">',
            '<div class="inc-audit-metrics-head">',
            # Slot filled by shared range select (cloned into visible panel by JS)
            '<div class="inc-audit-metrics-range-slot"></div>',
            "</div>",
            "".join(kpi_html),
            "</div>",
            # By CVE | By software
            '<div class="inc-audit-metrics-charts inc-audit-metrics-charts--2">',
            '<div class="inc-audit-metrics-chart">',
            "<h4>By CVE</h4>",
            f'{_hbar_rows_html(list(metrics.get("by_cve") or []), "No CVE scans")}',
            "</div>",
            '<div class="inc-audit-metrics-chart">',
            "<h4>By software</h4>",
            f'{_hbar_rows_html(list(metrics.get("by_software") or []), "No software-tagged scans")}',
            "</div>",
            "</div>",
            # By tool | By category
            '<div class="inc-audit-metrics-charts inc-audit-metrics-charts--2">',
            '<div class="inc-audit-metrics-chart">',
            "<h4>By tool</h4>",
            f'{_hbar_rows_html(list(metrics.get("by_tool") or []))}',
            "</div>",
            '<div class="inc-audit-metrics-chart">',
            "<h4>By category</h4>",
            f'{_hbar_rows_html(list(metrics.get("by_category") or []), "No category data")}',
            "</div>",
            "</div>",
            # Scans per day
            '<div class="inc-audit-metrics-charts inc-audit-metrics-charts--1">',
            '<div class="inc-audit-metrics-chart">',
            "<h4>Scans per day</h4>",
            f'{_day_bars_html(list(metrics.get("days") or []))}',
            "</div>",
            "</div>",
            # By operator
            '<div class="inc-audit-metrics-charts inc-audit-metrics-charts--1">',
            '<div class="inc-audit-metrics-chart">',
            "<h4>By operator</h4>",
            f'{_hbar_rows_html(list(metrics.get("by_operator") or []))}',
            "</div>",
            "</div>",
        ]
    )


def render_last7_metrics_html(metrics: dict | None = None, **panels: dict) -> str:
    """Option A dashboard: range dropdown + KPI/chart panels.

    Prefer calling render_metrics_dashboard() which builds all windows.
    This name remains for callers that only have a single metrics dict.
    """
    if panels:
        return render_metrics_dashboard(panels)
    if metrics is None:
        metrics = {}
    return render_metrics_dashboard({"7d": metrics})


def render_metrics_dashboard(by_window: dict[str, dict]) -> str:
    """Render metrics section with Today / Yesterday / Last 7 days / Last week / All panels."""
    # Shared select sits once; JS moves it into the visible panel's range slot.
    select_html = _metrics_range_select_html("7d")
    panel_chunks: list[str] = []
    for value, _label in _METRICS_RANGE_OPTIONS:
        if value not in by_window:
            continue
        metrics = by_window[value]
        hidden = " hidden" if value != "7d" else ""
        panel_chunks.append(
            f'<div class="inc-audit-metrics-panel" data-range="{html.escape(value, quote=True)}"'
            f"{hidden}>"
            f"{_render_metrics_panel_body(metrics)}"
            "</div>"
        )

    return "\n".join(
        [
            '<section class="inc-audit-section inc-audit-section--metrics" '
            'aria-label="Host-scan activity metrics">',
            '<div class="inc-audit-metrics" id="inc-audit-metrics">',
            # Select held here until JS places it in the visible panel head.
            f'<div class="inc-audit-metrics-range-holder" hidden>{select_html}</div>',
            *panel_chunks,
            "</div>",
            "</section>",
        ]
    )


def build_html(report_root: Path) -> str:
    mode = load_json(report_root / "assets" / "report-mode.json", {})
    mode_name = (mode.get("mode") or "operator").lower()

    audit_rows = load_audit_lines(report_root)
    host_rows = load_host_scan_summary(report_root)
    scan_output_index = build_host_scan_output_index(report_root)
    exports = load_exports(report_root)
    metrics_by_window = {
        "today": compute_metrics(report_root, audit_rows, "today"),
        "yesterday": compute_metrics(report_root, audit_rows, "yesterday"),
        "7d": compute_metrics(report_root, audit_rows, "7d"),
        "week": compute_metrics(report_root, audit_rows, "week"),
        "all": compute_metrics(report_root, audit_rows, "all"),
    }

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

    # Metrics strip with range dropdown (above Audit log)
    lines.append(render_metrics_dashboard(metrics_by_window))

    # Audit log (primary — above Target scans)
    lines.append('<section class="inc-audit-section inc-audit-section--log">')
    lines.append('<div class="inc-audit-log-header">')
    lines.append('<h3 class="inc-audit-section-title">Audit Log</h3>')
    # Slot filled by inc-audit-log-filter.js (operator dropdown).
    lines.append(
        '<div class="inc-audit-log-filter" id="inc-audit-log-filter" '
        'aria-label="Filter audit log by operator"></div>'
    )
    lines.append("</div>")
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
        for ts, operator, ip, action, raw_line in audit_rows:
            # Parse Target/Output from full action; show shortened Action text.
            out_cell = audit_output_cell(action, report_root, scan_output_index)
            op_disp = operator if operator else "—"
            ip_disp = _display_operator_ip(ip, action)
            target_disp = _display_audit_target(action)
            action_disp = _display_audit_action(
                action,
                report_root=report_root,
                scan_index=scan_output_index,
                ts=ts,
            )
            line_hash = audit_line_hash(raw_line)
            # Preview for delete confirm (time + short action).
            preview = f"{normalize_audit_display_ts(ts)} · {action_disp}"
            if len(preview) > 140:
                preview = preview[:137] + "."
            # data-audit-operator: raw name for filter (empty when legacy / missing).
            op_attr = (operator or "").strip()
            lines.append(
                f'<tr data-audit-hash="{html.escape(line_hash, quote=True)}" '
                f'data-audit-preview="{html.escape(preview, quote=True)}" '
                f'data-audit-operator="{html.escape(op_attr, quote=True)}">'
                f'<td class="inc-audit-col-time">{html.escape(normalize_audit_display_ts(ts))}</td>'
                f'<td class="inc-audit-col-op">{html.escape(op_disp)}</td>'
                f'<td class="inc-audit-col-ip">{html.escape(ip_disp)}</td>'
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

    # Target scans
    lines.append('<section class="inc-audit-section">')
    lines.append('<h3 class="inc-audit-section-title">Target scans</h3>')
    lines.append(
        '<div class="inc-content-frame inc-content-frame--table inc-audit-frame-wide">'
    )
    lines.append(
        '<table class="table table-bordered inc-data-table inc-audit-host-scans">'
    )
    # colgroup locks Target / tool widths under table-layout:fixed (Bootstrap-safe).
    tool_cols = "".join(
        '<col class="inc-audit-host-tool-col" />' for _ in HOST_SCAN_TOOLS
    )
    lines.append(
        "<colgroup>"
        '<col class="inc-audit-host-target-col" />'
        f"{tool_cols}"
        "</colgroup>"
    )
    tool_headers = "".join(
        f'<th scope="col" class="inc-sortable">{html.escape(label)}</th>'
        for _key, label in HOST_SCAN_TOOLS
    )
    lines.append(
        "<thead><tr>"
        '<th scope="col" class="inc-sortable inc-audit-host-target">Target</th>'
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
                f'<td class="inc-audit-host-target">{html.escape(row["host"])}</td>'
                + "".join(f"<td>{c}</td>" for c in cells)
                + "</tr>"
            )
    else:
        lines.append(
            f'<tr><td colspan="{1 + len(HOST_SCAN_TOOLS)}" class="inc-audit-muted inc-audit-empty">'
            "No host scans recorded yet.</td></tr>"
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
        '<th scope="col" class="inc-sortable inc-audit-col-exported">Time (UTC)</th>'
        '<th scope="col" class="inc-sortable">Type</th>'
        '<th scope="col" class="inc-sortable">Operator IPs</th>'
        '<th scope="col" class="inc-audit-col-file">File</th>'
        "</tr></thead><tbody>"
    )
    if exports:
        for exp in exports:
            kind = format_export_kind(str(exp.get("kind") or "client"))
            exported = format_export_time(exp)
            ips = "Included" if exp.get("include_operator_ips") else "Redacted"
            archive = exp.get("archive") or ""
            arch_cell = html.escape(os.path.basename(archive)) if archive else "—"
            lines.append(
                "<tr>"
                f'<td class="inc-audit-col-exported">{html.escape(exported)}</td>'
                f"<td>{html.escape(kind)}</td>"
                f"<td>{html.escape(ips)}</td>"
                f'<td class="inc-audit-col-file">{arch_cell}</td>'
                "</tr>"
            )
    else:
        lines.append(
            '<tr><td colspan="4" class="inc-audit-muted inc-audit-empty">No exports recorded yet.</td></tr>'
        )
    lines.append("</tbody></table></div></section>")

    return "\n".join(lines)


def write_defender_csv(report_root: Path, dest: Path) -> Path:
    """Write defender CSV using the same Action text as the Audit HTML page.

    Started host-scans → exact tool command; Finished → tool + duration.
    Same row filters as the Audit log (no Opened report / Exported noise).
    """
    import csv

    report_root = report_root.resolve()
    dest = Path(dest)
    scan_index = build_host_scan_output_index(report_root)
    rows_out: list[dict[str, str]] = []
    for ts, operator, ip, action, _raw in load_audit_lines(report_root):
        action_disp = _display_audit_action(
            action,
            report_root=report_root,
            scan_index=scan_index,
            ts=ts,
        )
        rows_out.append(
            {
                "time_utc": normalize_audit_display_ts(ts),
                "operator": operator,
                "operator_ip": ip,
                "target": audit_target_from_action(action) or "",
                "action": action_disp,
            }
        )

    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["time_utc", "operator", "operator_ip", "target", "action"],
            quoting=csv.QUOTE_MINIMAL,
        )
        writer.writeheader()
        writer.writerows(rows_out)
    return dest


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
    # Defender CSV: audit-build.py --defender-csv <report_root> <out.csv>
    if len(argv) >= 2 and argv[1] in {"--defender-csv", "-d"}:
        if len(argv) < 4:
            print(
                "Usage: audit-build.py --defender-csv <report_root> <out.csv>",
                file=sys.stderr,
            )
            return 2
        path = write_defender_csv(Path(argv[2]), Path(argv[3]))
        print(path)
        return 0

    # Delete one audit line by hash: audit-build.py --delete-line <sha256> <report> [--json]
    if len(argv) >= 2 and argv[1] in {"--delete-line", "--delete-audit-line"}:
        want_json = "--json" in argv
        args = [a for a in argv[2:] if a != "--json"]
        if len(args) < 2:
            print(
                "Usage: audit-build.py --delete-line <sha256> <report_root> [--json]",
                file=sys.stderr,
            )
            return 2
        line_hash, report = args[0], args[1]
        result = delete_audit_line_by_hash(Path(report), line_hash)
        if want_json:
            print(json.dumps(result, ensure_ascii=False))
        else:
            if result.get("ok"):
                print(result.get("summary") or "Deleted.")
            else:
                print(result.get("error") or "Delete failed.", file=sys.stderr)
        return 0 if result.get("ok") else 1

    if len(argv) < 2:
        print("Usage: audit-build.py <report_root> [template_audit.htm]", file=sys.stderr)
        print(
            "       audit-build.py --defender-csv <report_root> <out.csv>",
            file=sys.stderr,
        )
        print(
            "       audit-build.py --delete-line <sha256> <report_root> [--json]",
            file=sys.stderr,
        )
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
