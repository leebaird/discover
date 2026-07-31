#!/usr/bin/env python3
"""Merge another operator's Discover report package into a live engagement.

Usage:
  python3 recon/import-operator-package.py \\
    --dest /path/to/live-report \\
    --source /path/to/other-operator-report \\
    --operator Bob \\
    [--json]

Merges tools/host-scans, gowitness screenshots/jsonl, httpx/whatweb/active-alive,
subdomains (new hosts only), and matching audit log lines. Rebuilds Audit (and
Active/Subdomains when Active artifacts were merged). Never overwrites dest
pages from source HTML.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def is_report_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    pages = path / "pages"
    if not pages.is_dir():
        return False
    return any(
        (path / name).is_file() or (pages / name).is_file()
        for name in (
            "index.htm",
            "active.htm",
            "subdomains.htm",
            "passive.htm",
            "audit.htm",
        )
    )


def canonical_operator(name: str) -> str | None:
    """Return display name or None. Does not silently truncate oversize input."""
    raw = (name or "").strip()
    if not raw:
        return None
    # Reject non-letters and length > 10 before any truncation.
    if not re.fullmatch(r"[A-Za-z]{1,10}", raw):
        return None
    return raw[0].upper() + raw[1:].lower() if len(raw) > 1 else raw.upper()


def is_private_ip(ip: str) -> bool:
    if not IPV4_RE.match(ip or ""):
        return True
    o = [int(x) for x in ip.split(".")]
    if o[0] == 10:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    return False


def host_of_url(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return ""
    if "://" not in u:
        u = "https://" + u
    return (urlparse(u).hostname or "").lower()


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return default


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# --- host-scans ---


def merge_host_scans(dest: Path, source: Path) -> dict[str, int]:
    """Copy missing run dirs host/tool/stamp from source → dest."""
    src_base = source / "tools" / "host-scans"
    dst_base = dest / "tools" / "host-scans"
    stats = {"runs_copied": 0, "runs_skipped": 0, "hosts_touched": 0}
    if not src_base.is_dir():
        return stats

    dst_base.mkdir(parents=True, exist_ok=True)
    hosts_touched: set[str] = set()

    for host_dir in sorted(src_base.iterdir()):
        if not host_dir.is_dir() or host_dir.name in {"status.json", "statusd.port"}:
            continue
        if host_dir.name.endswith(".json") or host_dir.name.endswith(".port"):
            continue
        host = host_dir.name
        for tool_dir in sorted(host_dir.iterdir()):
            if not tool_dir.is_dir():
                continue
            tool = tool_dir.name
            for run_dir in sorted(tool_dir.iterdir()):
                if not run_dir.is_dir():
                    continue
                stamp = run_dir.name
                target = dst_base / host / tool / stamp
                if target.exists():
                    stats["runs_skipped"] += 1
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(run_dir, target)
                stats["runs_copied"] += 1
                hosts_touched.add(host)

    stats["hosts_touched"] = len(hosts_touched)
    rebuild_host_scan_status(dst_base)
    return stats


def rebuild_host_scan_status(scans_dir: Path) -> None:
    """Rebuild status.json + latest.json from all meta.json under host-scans.

    Prefer the newest run stamp (YYYYMMDDTHHMMSSZ). Never compare ISO finished_utc
    to stamp names — that left stale status=running entries winning after import.
    When stamps tie, prefer a finished meta over still-running.
    """
    hosts: dict[str, dict[str, dict]] = {}
    for meta_path in scans_dir.rglob("meta.json"):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(meta, dict):
            continue
        # path: host/tool/stamp/meta.json
        parts = meta_path.relative_to(scans_dir).parts
        if len(parts) < 3:
            continue
        host = str(meta.get("host") or parts[0]).strip().lower()
        tool = str(meta.get("tool") or parts[1]).strip().lower()
        stamp = parts[2]
        if not host or not tool:
            continue
        st = str(meta.get("status") or "").strip().lower()
        if not st:
            st = "done"
        finished_disp = str(
            meta.get("finished_display") or meta.get("finished") or ""
        ).strip()
        out = str(meta.get("output") or meta.get("output_rel") or "").strip()
        if not out:
            out = f"tools/host-scans/{host}/{tool}/{stamp}/output.txt"
        # Sort: stamp first; finished ranks above running so a killed mid-run
        # does not beat a completed rescan with the same stamp (should not happen)
        # or lose incorrectly when finished_utc was used as sort key.
        rank_finished = 0 if st == "running" else 1
        entry = {
            "status": st,
            "finished": finished_disp,
            "finished_display": finished_disp,
            "output": out,
            "output_rel": out,
            "software": meta.get("software") or "",
            "url": meta.get("url") or "",
            "_sort": (stamp, rank_finished),
        }
        if meta.get("skip_reason"):
            entry["skip_reason"] = meta.get("skip_reason")
        cur = hosts.setdefault(host, {}).get(tool)
        if cur is None or entry["_sort"] >= cur.get("_sort", ("", -1)):
            hosts.setdefault(host, {})[tool] = entry

    # strip internal sort key
    clean: dict[str, dict[str, dict]] = {}
    for host, tools in hosts.items():
        clean[host] = {}
        for tool, entry in tools.items():
            e = {k: v for k, v in entry.items() if k != "_sort"}
            clean[host][tool] = e
            latest = scans_dir / host / tool / "latest.json"
            latest.parent.mkdir(parents=True, exist_ok=True)
            latest.write_text(json.dumps(e, indent=2) + "\n", encoding="utf-8")

    status = {
        "hosts": clean,
        "running": False,
        "current": None,
    }
    write_json(scans_dir / "status.json", status)


# --- gowitness ---


def merge_gowitness(dest: Path, source: Path) -> dict[str, int]:
    stats = {"screenshots_copied": 0, "screenshots_skipped": 0, "jsonl_added": 0}
    src_shots = source / "tools" / "gowitness" / "screenshots"
    dst_shots = dest / "tools" / "gowitness" / "screenshots"
    if src_shots.is_dir():
        dst_shots.mkdir(parents=True, exist_ok=True)
        for f in src_shots.iterdir():
            if not f.is_file():
                continue
            target = dst_shots / f.name
            if target.exists():
                stats["screenshots_skipped"] += 1
                continue
            shutil.copy2(f, target)
            stats["screenshots_copied"] += 1

    src_jsonl = source / "tools" / "gowitness" / "gowitness.jsonl"
    dst_jsonl = dest / "tools" / "gowitness" / "gowitness.jsonl"
    if not src_jsonl.is_file():
        return stats

    existing_hosts: set[str] = set()
    existing_files: set[str] = set()
    kept_lines: list[str] = []
    if dst_jsonl.is_file():
        for raw in dst_jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                e = json.loads(raw)
            except json.JSONDecodeError:
                kept_lines.append(raw)
                continue
            h = host_of_url(str(e.get("url") or e.get("final_url") or ""))
            fn = str(e.get("file_name") or "").strip()
            if h:
                existing_hosts.add(h)
            if fn:
                existing_files.add(fn)
            kept_lines.append(raw)

    added = 0
    for raw in src_jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            e = json.loads(raw)
        except json.JSONDecodeError:
            continue
        h = host_of_url(str(e.get("url") or e.get("final_url") or ""))
        fn = str(e.get("file_name") or "").strip()
        # Skip if we already have this screenshot file or same host entry
        if fn and fn in existing_files:
            continue
        if h and h in existing_hosts and not fn:
            continue
        if h and h in existing_hosts and fn and fn not in existing_files:
            # new screenshot for known host — keep
            pass
        elif h and h in existing_hosts:
            continue
        kept_lines.append(raw)
        added += 1
        if h:
            existing_hosts.add(h)
        if fn:
            existing_files.add(fn)

    stats["jsonl_added"] = added
    dst_jsonl.parent.mkdir(parents=True, exist_ok=True)
    dst_jsonl.write_text(
        "\n".join(kept_lines) + ("\n" if kept_lines else ""),
        encoding="utf-8",
    )
    return stats


# --- httpx / whatweb / alive ---


def merge_httpx(dest: Path, source: Path) -> dict[str, int]:
    stats = {"hosts_merged": 0, "lines_dest": 0, "lines_src": 0}
    src = source / "tools" / "httpx.jsonl"
    dst = dest / "tools" / "httpx.jsonl"
    if not src.is_file():
        return stats

    by_host: dict[str, str] = {}

    def ingest(path: Path, prefer: bool) -> int:
        n = 0
        if not path.is_file():
            return 0
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                e = json.loads(raw)
            except json.JSONDecodeError:
                continue
            host = str(e.get("host") or e.get("input") or "").strip().lower().split(":")[0]
            if not host:
                url = str(e.get("url") or "")
                host = host_of_url(url)
            if not host:
                continue
            n += 1
            if prefer or host not in by_host:
                by_host[host] = raw
        return n

    stats["lines_dest"] = ingest(dst, prefer=False)
    before = len(by_host)
    stats["lines_src"] = ingest(src, prefer=True)
    stats["hosts_merged"] = max(0, len(by_host) - before)

    lines = [by_host[h] for h in sorted(by_host)]
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return stats


def merge_whatweb(dest: Path, source: Path) -> dict[str, int]:
    stats = {"entries_merged": 0}
    src = source / "tools" / "whatweb.json"
    dst = dest / "tools" / "whatweb.json"
    if not src.is_file():
        return stats

    def load_list(path: Path) -> list:
        if not path.is_file() or path.stat().st_size == 0:
            return []
        data = load_json(path, [])
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []

    def target_host(entry: Any) -> str:
        if not isinstance(entry, dict):
            return ""
        t = str(entry.get("target") or entry.get("uri") or "")
        return host_of_url(t) if t else ""

    main = load_list(dst)
    batch = load_list(src)
    batch_hosts = {target_host(e) for e in batch if target_host(e)}
    kept = [e for e in main if target_host(e) not in batch_hosts]
    merged = kept + batch
    stats["entries_merged"] = len(batch_hosts)
    write_json(dst, merged)
    return stats


def rebuild_active_alive(dest: Path) -> int:
    """Rebuild active-alive.tsv + active.txt from httpx.jsonl (same alive rules as Active)."""
    httpx_path = dest / "tools" / "httpx.jsonl"
    alive_tsv = dest / "tools" / "active-alive.tsv"
    active_txt = dest / "tools" / "active.txt"
    ALIVE = set(range(200, 400)) | {401, 403, 405}
    rows: list[tuple[str, str, int]] = []
    urls: set[str] = set()
    if httpx_path.is_file():
        for raw in httpx_path.read_text(encoding="utf-8", errors="replace").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                e = json.loads(raw)
            except json.JSONDecodeError:
                continue
            status = e.get("status_code")
            if status is None:
                continue
            try:
                status_i = int(status)
            except (TypeError, ValueError):
                continue
            if status_i not in ALIVE:
                continue
            host = str(e.get("host") or e.get("input") or "").strip().lower().split(":")[0]
            url = str(e.get("url") or "").strip()
            if not host or not url:
                continue
            rows.append((host, url, status_i))
            urls.add(url)
    alive_tsv.parent.mkdir(parents=True, exist_ok=True)
    alive_tsv.write_text(
        "".join(f"{h}\t{u}\t{s}\n" for h, u, s in rows),
        encoding="utf-8",
    )
    active_txt.write_text(
        "\n".join(sorted(urls)) + ("\n" if urls else ""),
        encoding="utf-8",
    )
    return len(rows)


# --- subdomains ---


def merge_subdomains(dest: Path, source: Path) -> dict[str, int]:
    stats = {"new_hosts": 0, "dest_hosts": 0, "src_hosts": 0}
    src = source / "tools" / "subdomains"
    dst = dest / "tools" / "subdomains"
    if not src.is_file():
        return stats

    def load_map(path: Path) -> dict[str, str]:
        out: dict[str, str] = {}
        if not path.is_file():
            return out
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            host = parts[0].strip().lower()
            if host.startswith("www."):
                host = host[4:]
            if not host:
                continue
            # keep original line body for write
            out[host] = line
        return out

    dest_map = load_map(dst)
    src_map = load_map(src)
    stats["dest_hosts"] = len(dest_map)
    stats["src_hosts"] = len(src_map)
    for host, line in src_map.items():
        if host not in dest_map:
            dest_map[host] = line
            stats["new_hosts"] += 1

    lines = [dest_map[h] for h in sorted(dest_map)]
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    # private-subs from dest
    priv_rows = []
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        host, ip = parts[0].strip(), parts[1].strip()
        if ip and is_private_ip(ip):
            priv_rows.append(line)
    priv = dest / "tools" / "private-subs"
    priv.write_text(
        "\n".join(sorted(priv_rows, key=str.lower)) + ("\n" if priv_rows else ""),
        encoding="utf-8",
    )
    return stats


# --- audit ---

# Current:  mm-dd-yyyy - hh:mm Z | op | ip | action
# Legacy:   mm-dd-yyyy Z - hh:mm | op | ip | action  (Z before the dash)
_AUDIT_TS = (
    r"(?:"
    r"\d{2}-\d{2}-\d{4}\s+-\s+\d{2}:\d{2}\s+Z"  # current
    r"|"
    r"\d{2}-\d{2}-\d{4}\s+Z\s+-\s+\d{2}:\d{2}"  # legacy
    r")"
)
_AUDIT_LINE_RE = re.compile(
    rf"^({_AUDIT_TS})\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*(.+)$"
)
# Legacy 3-field: time | ip | action (no operator)
_AUDIT_LINE_RE3 = re.compile(
    rf"^({_AUDIT_TS})\s*\|\s*([^|]+)\s*\|\s*(.+)$"
)


def list_source_operators(source: Path) -> list[str]:
    """Unique operator names (display form) found in source audit log."""
    src_log = source / "tools" / "audit" / "log.txt"
    found: dict[str, str] = {}  # lower -> display
    if not src_log.is_file():
        return []
    for raw in src_log.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _AUDIT_LINE_RE.match(line)
        if not m:
            continue
        op_field = m.group(2).strip()
        if not op_field:
            continue
        key = op_field.lower()
        if key not in found:
            # Prefer canonical casing when possible
            c = canonical_operator(op_field)
            found[key] = c or op_field
    return sorted(found.values(), key=str.lower)


def count_operator_audit_lines(source: Path, operator: str) -> int:
    op_l = operator.lower()
    src_log = source / "tools" / "audit" / "log.txt"
    if not src_log.is_file():
        return 0
    n = 0
    for raw in src_log.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _AUDIT_LINE_RE.match(line)
        if not m:
            continue
        if m.group(2).strip().lower() == op_l:
            n += 1
    return n


def merge_audit_log(dest: Path, source: Path, operator: str) -> dict[str, int]:
    """Append source audit lines for this operator that dest does not already have."""
    stats = {"lines_appended": 0, "lines_matched": 0}
    src_log = source / "tools" / "audit" / "log.txt"
    dst_log = dest / "tools" / "audit" / "log.txt"
    if not src_log.is_file():
        return stats

    existing: set[str] = set()
    if dst_log.is_file():
        for raw in dst_log.read_text(encoding="utf-8", errors="replace").splitlines():
            existing.add(raw.strip())

    op_l = operator.lower()
    to_add: list[str] = []
    for raw in src_log.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _AUDIT_LINE_RE.match(line)
        if not m:
            continue
        op_field = m.group(2).strip()
        if op_field.lower() != op_l:
            continue
        stats["lines_matched"] += 1
        if line in existing:
            continue
        to_add.append(line)
        existing.add(line)

    if to_add:
        dst_log.parent.mkdir(parents=True, exist_ok=True)
        with dst_log.open("a", encoding="utf-8") as handle:
            for line in to_add:
                handle.write(line + "\n")
        stats["lines_appended"] = len(to_add)
    return stats


def append_import_audit(dest: Path, operator: str, summary: str) -> None:
    audit_dir = dest / "tools" / "audit"
    audit_log = audit_dir / "log.txt"
    audit_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%m-%d-%Y - %H:%M Z")
    op = "unknown"
    try:
        op_path = Path.home() / ".discover" / "operator-name"
        if op_path.is_file():
            raw = op_path.read_text(encoding="utf-8", errors="replace").splitlines()[0].strip()
            c = re.sub(r"[^A-Za-z]", "", raw)[:10]
            if c:
                op = c[0].upper() + c[1:].lower() if len(c) > 1 else c.upper()
    except OSError:
        pass
    action = f"Imported operator package ({operator}: {summary})."
    # No egress IP for package imports
    line = f"{ts} | {op} | - | {action}\n"
    with audit_log.open("a", encoding="utf-8") as handle:
        handle.write(line)


def rebuild_pages(dest: Path, discover: Path, *, did_active_merge: bool) -> list[str]:
    rebuilt: list[str] = []
    env = os.environ.copy()
    env["DISCOVER"] = str(discover)

    audit_build = discover / "recon" / "audit-build.py"
    audit_tpl = discover / "report" / "pages" / "audit.htm"
    if audit_build.is_file():
        try:
            subprocess.run(
                [sys.executable, str(audit_build), str(dest), str(audit_tpl)],
                check=False,
                capture_output=True,
                timeout=120,
                env=env,
                cwd=str(discover),
            )
            rebuilt.append("audit.htm")
        except Exception as exc:
            eprint(f"[!] audit rebuild: {exc}")

    if did_active_merge:
        active_tech = discover / "recon" / "active-tech.py"
        if active_tech.is_file() and (dest / "tools" / "httpx.jsonl").is_file():
            try:
                subprocess.run(
                    [
                        sys.executable,
                        str(active_tech),
                        str(dest),
                        "--refresh-cves",
                        "--skip-audit",
                    ],
                    check=False,
                    capture_output=True,
                    timeout=600,
                    env=env,
                    cwd=str(discover),
                )
                rebuilt.append("active.htm")
            except Exception as exc:
                eprint(f"[!] active rebuild: {exc}")

        # Subdomains Active columns via active.sh writer is heavy; try python path from active-tech
        # Prefer light: call active.sh report-only is not available. Rebuild subdomains if we can
        # import the write from a small subprocess using discover's active merge logic is complex.
        # Use active-tech rebuild only; import-report can refresh. Optional: run audit only.

    return rebuilt


def discover_root() -> Path:
    env = (os.environ.get("DISCOVER") or "").strip()
    if env and Path(env).is_dir():
        return Path(env).resolve()
    return Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Merge operator package into live report")
    parser.add_argument("--dest", required=True, help="Live engagement report directory")
    parser.add_argument("--source", required=True, help="Unpacked operator report directory")
    parser.add_argument("--operator", required=True, help="Other operator first name (max 10 letters)")
    parser.add_argument("--json", action="store_true", help="Print JSON result on stdout")
    args = parser.parse_args(argv)

    dest = Path(os.path.expanduser(args.dest)).resolve()
    source = Path(os.path.expanduser(args.source)).resolve()
    operator = canonical_operator(args.operator)

    result: dict[str, Any] = {
        "ok": False,
        "dest": str(dest),
        "source": str(source),
        "operator": operator or args.operator,
    }

    def fail(msg: str, code: int = 1) -> int:
        result["error"] = msg
        if args.json:
            print(json.dumps(result, separators=(",", ":")))
        else:
            eprint(f"[!] {msg}")
        return code

    if not operator:
        # Distinguish empty / too long / bad chars when raw input known
        raw_op = (args.operator or "").strip()
        if not raw_op:
            return fail("Operator name is required (first name, 1–10 letters).")
        if len(re.sub(r"[^A-Za-z]", "", raw_op)) > 10 or len(raw_op) > 10:
            return fail(
                f"Operator name is too long (max 10 letters). You entered {len(raw_op)} characters."
            )
        return fail("Operator name must be 1–10 letters only (no spaces or numbers).")

    if not is_report_dir(dest):
        return fail(f"Destination is not a Discover report: {dest}")

    if not is_report_dir(source):
        return fail(
            f"Source is not a Discover report directory: {source}. "
            "Point to the unpacked report folder (with pages/ and tools/)."
        )

    if dest == source:
        return fail("Source and destination are the same path.")

    # Soft check: export-meta kind
    meta = load_json(source / "export-meta.json", {})
    if isinstance(meta, dict) and meta.get("kind") and str(meta.get("kind")).lower() == "client":
        return fail("Refusing client export (use an Operator package with full tools/).")

    # Operator must appear in their audit log (prevents Samuelasdf → silent 0 lines).
    matched = count_operator_audit_lines(source, operator)
    if matched == 0:
        known = list_source_operators(source)
        if not (source / "tools" / "audit" / "log.txt").is_file():
            return fail(
                f"No audit log in the source report (tools/audit/log.txt). "
                f"Cannot verify operator “{operator}”."
            )
        if known:
            names = ", ".join(known)
            return fail(
                f"No audit lines for operator “{operator}”. "
                f"Names found in that report: {names}."
            )
        return fail(
            f"No audit lines for operator “{operator}”, and no operator names "
            "were found in that report’s audit log."
        )

    disc = discover_root()
    stats: dict[str, Any] = {}

    stats["host_scans"] = merge_host_scans(dest, source)
    stats["gowitness"] = merge_gowitness(dest, source)
    stats["httpx"] = merge_httpx(dest, source)
    stats["whatweb"] = merge_whatweb(dest, source)
    did_active = bool(
        stats["httpx"].get("lines_src")
        or stats["whatweb"].get("entries_merged")
        or stats["gowitness"].get("screenshots_copied")
        or stats["gowitness"].get("jsonl_added")
    )
    if did_active or (dest / "tools" / "httpx.jsonl").is_file():
        stats["alive_rows"] = rebuild_active_alive(dest)
    stats["subdomains"] = merge_subdomains(dest, source)
    stats["audit"] = merge_audit_log(dest, source, operator)

    summary_bits = [
        f"{stats['host_scans'].get('runs_copied', 0)} host-scan runs",
        f"{stats['gowitness'].get('screenshots_copied', 0)} screenshots",
        f"{stats['subdomains'].get('new_hosts', 0)} new hosts",
        f"{stats['audit'].get('lines_appended', 0)} audit lines",
    ]
    summary = ", ".join(summary_bits)
    append_import_audit(dest, operator, summary)
    stats["rebuilt"] = rebuild_pages(dest, disc, did_active_merge=did_active)

    try:
        touch_path = Path(__file__).resolve().parent / "touch-report-date.py"
        if touch_path.is_file():
            import importlib.util as _ilu

            _spec = _ilu.spec_from_file_location("touch_report_date", str(touch_path))
            if _spec is not None and _spec.loader is not None:
                _mod = _ilu.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)
                _mod.touch_report_index_date(dest)
    except Exception:
        pass

    result["ok"] = True
    result["stats"] = stats
    result["summary"] = summary
    result["operator"] = operator

    if args.json:
        print(json.dumps(result, separators=(",", ":")))
    else:
        print(f"[*] Imported operator package from {source}")
        print(f"    Operator: {operator}")
        print(f"    {summary}")
        print(f"    Rebuilt: {', '.join(stats.get('rebuilt') or []) or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
