#!/usr/bin/env python3
"""Enrich Discover engagement hosts with Shodan host-by-IP data.

Phase 1: collect unique public IPs from Active httpx output, query the
Shodan host API (membership / paid keys), write artifacts under
``tools/shodan/``, and append an Audit log line.

SHODAN_API_KEY is required. Discover checks, in order:
  1. Existing shell environment (export SHODAN_API_KEY=...)
  2. Private .env files (never override a non-empty shell export):
       $DISCOVER/.env
       ~/.discover/.env

IP lookups do not consume Shodan query credits. Rate-limit with a short
sleep between requests (default 1.1s). Resume skips IPs that already have
a successful cache file under tools/shodan/hosts/.

Usage:
  python3 recon/shodan-enrich.py <report_dir> [--force] [--limit N] [--sleep SEC]
  python3 recon/shodan-enrich.py <report_dir> --dry-run
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

SHODAN_HOST_API = "https://api.shodan.io/shodan/host/{ip}"
USER_AGENT = "Discover-shodan-enrich/1.0 (https://github.com/leebaird/discover)"
DEFAULT_SLEEP = 1.1
CACHE_VERSION = 1
SUMMARY_VERSION = 1
_ENV_FILES_LOADED = False


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def _discover_root() -> str:
    explicit = (os.environ.get("DISCOVER") or "").strip()
    if explicit:
        return explicit
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_software_cve_module() -> Any | None:
    """Load recon/software-cve.py (hyphenated filename) when available."""
    module_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "software-cve.py")
    if not os.path.isfile(module_path):
        return None
    try:
        spec = importlib.util.spec_from_file_location("software_cve", module_path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def _parse_env_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("export "):
        line = line[7:].strip()
    if "=" not in line:
        return None
    key, _, value = line.partition("=")
    key = key.strip()
    if not key or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return key, value


def load_discover_env_files() -> list[str]:
    """Load KEY=VALUE from private .env files (shell exports win).

    Prefers software-cve.py's loader when present so NVD/Shodan share one path.
    """
    global _ENV_FILES_LOADED
    software_cve = _load_software_cve_module()
    if software_cve is not None and hasattr(software_cve, "load_discover_env_files"):
        loaded = software_cve.load_discover_env_files()
        _ENV_FILES_LOADED = True
        return list(loaded or [])

    loaded: list[str] = []
    candidates = [
        os.path.join(_discover_root(), ".env"),
        os.path.join(os.path.expanduser("~"), ".discover", ".env"),
    ]
    seen: set[str] = set()
    for path in candidates:
        abs_path = os.path.abspath(path)
        if abs_path in seen or not os.path.isfile(abs_path):
            continue
        seen.add(abs_path)
        try:
            with open(abs_path, encoding="utf-8") as handle:
                for raw in handle:
                    parsed = _parse_env_line(raw)
                    if not parsed:
                        continue
                    key, value = parsed
                    if (os.environ.get(key) or "").strip():
                        continue
                    os.environ[key] = value
            loaded.append(abs_path)
        except OSError:
            continue
    _ENV_FILES_LOADED = True
    return loaded


def get_shodan_api_key() -> str:
    if not _ENV_FILES_LOADED:
        load_discover_env_files()
    return (os.environ.get("SHODAN_API_KEY") or "").strip()


def is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return bool(addr.is_global)


def collect_ips_from_httpx(httpx_path: str) -> list[str]:
    """Unique public IPs from tools/httpx.jsonl (host_ip, then a[])."""
    seen: set[str] = set()
    ordered: list[str] = []

    def add(raw: object) -> None:
        if raw is None:
            return
        if isinstance(raw, list):
            for item in raw:
                add(item)
            return
        text = str(raw).strip()
        if not text or text in seen:
            return
        if not is_public_ip(text):
            return
        seen.add(text)
        ordered.append(text)

    if not os.path.isfile(httpx_path):
        return ordered

    with open(httpx_path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            add(row.get("host_ip"))
            add(row.get("a"))
            add(row.get("ip"))
            # Some httpx builds nest under "input"
            inp = row.get("input")
            if isinstance(inp, dict):
                add(inp.get("host_ip") or inp.get("ip"))

    return ordered


def host_cache_path(shodan_dir: str, ip: str) -> str:
    # Filesystem-safe name (IPv4 dots ok; IPv6 colons -> underscores)
    safe = ip.replace(":", "_")
    return os.path.join(shodan_dir, "hosts", f"{safe}.json")


def load_cached_host(path: str) -> dict[str, Any] | None:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            return None
        # Only skip when we previously got a terminal result (ok or not_found)
        status = (data.get("discover_status") or "").strip()
        if status in {"ok", "not_found"}:
            return data
        return None
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None


def shodan_host_lookup(ip: str, api_key: str, timeout: float = 45.0) -> dict[str, Any]:
    """Call Shodan host API. Returns a Discover-wrapped record."""
    params = urllib.parse.urlencode({"key": api_key})
    url = f"{SHODAN_HOST_API.format(ip=urllib.parse.quote(ip))}?{params}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        },
    )
    fetched_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            payload = json.loads(body)
            if not isinstance(payload, dict):
                return {
                    "ip": ip,
                    "discover_status": "error",
                    "discover_error": "unexpected_response_type",
                    "fetched_at": fetched_at,
                    "cache_version": CACHE_VERSION,
                }
            return {
                "ip": ip,
                "discover_status": "ok",
                "fetched_at": fetched_at,
                "cache_version": CACHE_VERSION,
                "shodan": payload,
            }
    except urllib.error.HTTPError as exc:
        err_body = ""
        try:
            err_body = exc.read().decode("utf-8", errors="replace")
        except OSError:
            pass
        # 404 = IP not in Shodan (normal for many hosts)
        if exc.code == 404:
            return {
                "ip": ip,
                "discover_status": "not_found",
                "fetched_at": fetched_at,
                "cache_version": CACHE_VERSION,
                "http_status": 404,
            }
        msg = f"http_{exc.code}"
        try:
            err_json = json.loads(err_body) if err_body else {}
            if isinstance(err_json, dict) and err_json.get("error"):
                msg = str(err_json.get("error"))
        except (json.JSONDecodeError, TypeError, ValueError):
            if err_body:
                msg = err_body[:200]
        return {
            "ip": ip,
            "discover_status": "error",
            "discover_error": msg,
            "http_status": exc.code,
            "fetched_at": fetched_at,
            "cache_version": CACHE_VERSION,
        }
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
        return {
            "ip": ip,
            "discover_status": "error",
            "discover_error": str(exc)[:300],
            "fetched_at": fetched_at,
            "cache_version": CACHE_VERSION,
        }


def summarize_record(rec: dict[str, Any]) -> dict[str, Any]:
    """Flatten one host record for summary.json / TSV."""
    ip = rec.get("ip") or ""
    status = rec.get("discover_status") or ""
    row: dict[str, Any] = {
        "ip": ip,
        "status": status,
        "org": "",
        "isp": "",
        "os": "",
        "country": "",
        "city": "",
        "ports": "",
        "port_count": 0,
        "hostnames": "",
        "vuln_count": 0,
        "vulns": "",
        "last_update": "",
        "fetched_at": rec.get("fetched_at") or "",
    }
    if status != "ok":
        row["error"] = rec.get("discover_error") or (
            "not in Shodan" if status == "not_found" else ""
        )
        return row

    sh = rec.get("shodan") if isinstance(rec.get("shodan"), dict) else {}
    row["org"] = str(sh.get("org") or "")
    row["isp"] = str(sh.get("isp") or "")
    row["os"] = str(sh.get("os") or "")
    row["country"] = str(sh.get("country_code") or sh.get("country_name") or "")
    row["city"] = str(sh.get("city") or "")
    row["last_update"] = str(sh.get("last_update") or "")

    ports = sh.get("ports") or []
    if isinstance(ports, list):
        port_strs = sorted({str(p) for p in ports if p is not None}, key=lambda x: int(x) if x.isdigit() else 0)
        row["ports"] = ",".join(port_strs)
        row["port_count"] = len(port_strs)

    hostnames = sh.get("hostnames") or []
    if isinstance(hostnames, list):
        row["hostnames"] = ", ".join(str(h) for h in hostnames if h)

    vulns = sh.get("vulns") or []
    if isinstance(vulns, dict):
        vuln_ids = sorted(vulns.keys())
    elif isinstance(vulns, list):
        vuln_ids = sorted(str(v) for v in vulns)
    else:
        vuln_ids = []
    row["vuln_count"] = len(vuln_ids)
    row["vuln_ids"] = vuln_ids  # full list for Subdomains UI / index.js
    # TSV-friendly truncated string
    row["vulns"] = ",".join(vuln_ids[:40])
    if len(vuln_ids) > 40:
        row["vulns"] += f",…(+{len(vuln_ids) - 40})"
    return row


def write_json(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=False)
        handle.write("\n")


def write_summary_tsv(path: str, rows: list[dict[str, Any]]) -> None:
    fields = [
        "ip",
        "status",
        "org",
        "isp",
        "os",
        "country",
        "city",
        "port_count",
        "ports",
        "vuln_count",
        "vulns",
        "hostnames",
        "last_update",
        "fetched_at",
        "error",
    ]
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", delimiter="\t")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def append_audit_log(report_dir: str, action: str) -> None:
    audit_dir = os.path.join(report_dir, "tools", "audit")
    audit_log = os.path.join(audit_dir, "log.txt")
    try:
        os.makedirs(audit_dir, exist_ok=True)
    except OSError:
        return
    ts = datetime.now(timezone.utc).strftime("%m-%d-%Y Z - %H:%M")
    if not action.endswith("."):
        action = action + "."
    # Egress IP: leave as unknown here; shell wrapper uses f_audit_log when available.
    line = f"{ts} | unknown | {action}\n"
    try:
        with open(audit_log, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        pass


def rebuild_audit_page(report_dir: str) -> None:
    discover = (os.environ.get("DISCOVER") or "").strip()
    if not discover:
        discover = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    builder = os.path.join(discover, "recon", "audit-build.py")
    template = os.path.join(discover, "report", "pages", "audit.htm")
    if not os.path.isfile(builder):
        return
    import subprocess

    cmd = [sys.executable, builder, report_dir]
    if os.path.isfile(template):
        cmd.append(template)
    try:
        subprocess.run(cmd, check=False, capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Enrich Discover report IPs with Shodan host data.",
    )
    parser.add_argument(
        "report_dir",
        help="Path to engagement report root (contains tools/ and pages/)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-query IPs even when a successful cache file exists",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Max IPs to query this run (0 = all; useful for smoke tests)",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=DEFAULT_SLEEP,
        help=f"Seconds between API calls (default {DEFAULT_SLEEP})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List IPs that would be queried; do not call Shodan",
    )
    parser.add_argument(
        "--skip-audit",
        action="store_true",
        help="Do not append audit log or rebuild audit.htm (shell wrapper handles it)",
    )
    args = parser.parse_args(argv)

    report_dir = os.path.abspath(os.path.expanduser(args.report_dir))
    if not os.path.isdir(report_dir):
        eprint(f"[!] Report directory not found: {report_dir}")
        return 1
    if not os.path.isdir(os.path.join(report_dir, "pages")):
        eprint(f"[!] Not a Discover report (missing pages/): {report_dir}")
        return 1

    httpx_path = os.path.join(report_dir, "tools", "httpx.jsonl")
    if not os.path.isfile(httpx_path):
        eprint(f"[!] No Active httpx data at tools/httpx.jsonl")
        eprint("    Run Active recon first, then re-run Shodan enrichment.")
        return 1

    ips = collect_ips_from_httpx(httpx_path)
    if not ips:
        eprint("[!] No public IPs found in tools/httpx.jsonl")
        return 1

    print(f"[*] Report:  {report_dir}", flush=True)
    print(f"[*] Source:  tools/httpx.jsonl", flush=True)
    print(f"[*] Public IPs found: {len(ips)}", flush=True)

    if args.dry_run:
        limit = args.limit if args.limit and args.limit > 0 else len(ips)
        print(f"[*] Dry-run — would query up to {min(limit, len(ips))} IP(s):", flush=True)
        for ip in ips[:limit]:
            print(f"    {ip}", flush=True)
        if len(ips) > limit:
            print(f"    … and {len(ips) - limit} more", flush=True)
        return 0

    api_key = get_shodan_api_key()
    if not api_key:
        print("[!] SHODAN_API_KEY not set — skipping Shodan enrichment.", flush=True)
        print("    export SHODAN_API_KEY=... or add it to $DISCOVER/.env / ~/.discover/.env", flush=True)
        print("    See .env.example and README (Shodan enrichment).", flush=True)
        return 0  # soft skip — not a hard failure

    shodan_dir = os.path.join(report_dir, "tools", "shodan")
    hosts_dir = os.path.join(shodan_dir, "hosts")
    os.makedirs(hosts_dir, exist_ok=True)

    to_query = ips
    if args.limit and args.limit > 0:
        to_query = ips[: args.limit]
        print(f"[*] Limit:   {args.limit} IP(s) this run")

    stats = {
        "queried": 0,
        "cached": 0,
        "ok": 0,
        "not_found": 0,
        "error": 0,
    }
    all_records: list[dict[str, Any]] = []
    sleep_s = max(0.0, float(args.sleep))
    total = len(to_query)
    need_sleep = False

    for idx, ip in enumerate(to_query, start=1):
        cache_path = host_cache_path(shodan_dir, ip)
        if not args.force:
            cached = load_cached_host(cache_path)
            if cached is not None:
                stats["cached"] += 1
                all_records.append(cached)
                status = cached.get("discover_status") or "?"
                if status == "ok":
                    stats["ok"] += 1
                elif status == "not_found":
                    stats["not_found"] += 1
                print(f"[{idx}/{total}] {ip}  (cached: {status})")
                continue

        if need_sleep and sleep_s > 0:
            time.sleep(sleep_s)
        need_sleep = True

        print(f"[{idx}/{total}] {ip}  querying…", end="", flush=True)
        rec = shodan_host_lookup(ip, api_key)
        stats["queried"] += 1
        status = rec.get("discover_status") or "error"
        if status == "ok":
            stats["ok"] += 1
            ports = (rec.get("shodan") or {}).get("ports") if isinstance(rec.get("shodan"), dict) else None
            nports = len(ports) if isinstance(ports, list) else 0
            print(f" ok ({nports} port(s))")
        elif status == "not_found":
            stats["not_found"] += 1
            print(" not in Shodan")
        else:
            stats["error"] += 1
            print(f" error: {rec.get('discover_error') or 'unknown'}")
            # Back off harder on rate limits
            if rec.get("http_status") == 429:
                eprint("    [!] Rate limited — sleeping 5s")
                time.sleep(5.0)

        # Persist errors too so operators can inspect; resume only skips ok/not_found
        write_json(cache_path, rec)
        all_records.append(rec)

    # Include cached IPs beyond --limit only when no limit? Keep summary to this run set.
    # Also load any other host caches for a full-directory summary when not limited.
    if not args.limit:
        known = {r.get("ip") for r in all_records}
        for name in os.listdir(hosts_dir) if os.path.isdir(hosts_dir) else []:
            if not name.endswith(".json"):
                continue
            path = os.path.join(hosts_dir, name)
            rec = load_cached_host(path)
            if rec and rec.get("ip") not in known:
                all_records.append(rec)
                known.add(rec.get("ip"))

    # Sort by IP for stable output
    def _ip_sort_key(rec: dict[str, Any]) -> tuple:
        ip = str(rec.get("ip") or "")
        try:
            return (0, ipaddress.ip_address(ip).packed)
        except ValueError:
            return (1, ip.encode())

    all_records.sort(key=_ip_sort_key)
    summary_rows = [summarize_record(r) for r in all_records]

    summary = {
        "version": SUMMARY_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "report": report_dir,
        "source": "tools/httpx.jsonl",
        "api": "shodan/host",
        "public_ips_in_httpx": len(ips),
        "stats": stats,
        "hosts": summary_rows,
    }
    write_json(os.path.join(shodan_dir, "summary.json"), summary)
    write_summary_tsv(os.path.join(shodan_dir, "summary.tsv"), summary_rows)

    # Compact index of IP → fields for Subdomains UI / other tools
    index = {
        row["ip"]: {
            "status": row["status"],
            "org": row["org"],
            "isp": row.get("isp") or "",
            "city": row.get("city") or "",
            "country": row.get("country") or "",
            "ports": row["ports"],
            "vuln_count": row["vuln_count"],
            "vulns": row.get("vuln_ids") or [],
            "hostnames": row["hostnames"],
        }
        for row in summary_rows
        if row.get("ip")
    }
    write_json(os.path.join(shodan_dir, "index.json"), index)

    # Browser-friendly index for Subdomains UI (file:// cannot fetch .json).
    index_js_path = os.path.join(shodan_dir, "index.js")
    try:
        with open(index_js_path, "w", encoding="utf-8") as handle:
            handle.write(
                "/* Generated by shodan-enrich.py — do not edit. */\n"
                "window.DISCOVER_SHODAN_INDEX = "
            )
            json.dump(index, handle, indent=None, sort_keys=True, separators=(",", ":"))
            handle.write(";\n")
    except OSError as exc:
        eprint(f"[!] Could not write {index_js_path}: {exc}")

    print()
    print(f"[*] Done. Queried={stats['queried']}  cached={stats['cached']}  "
          f"ok={stats['ok']}  not_found={stats['not_found']}  error={stats['error']}")
    print(f"[*] Artifacts: {shodan_dir}/")
    print(f"    hosts/*.json   per-IP Shodan response")
    print(f"    summary.json   aggregate + stats")
    print(f"    summary.tsv    spreadsheet-friendly")
    print(f"    index.json     IP → ports/org/hostnames")
    print(f"    index.js       Subdomains UI (file:// safe)")

    if not args.skip_audit:
        action = (
            f"Ran Shodan enrichment ({stats['ok']} with data, "
            f"{stats['not_found']} not in Shodan, {stats['error']} errors; "
            f"{stats['queried']} queried, {stats['cached']} cached)"
        )
        append_audit_log(report_dir, action)
        rebuild_audit_page(report_dir)

    # Hard fail only if every live query errored and nothing useful remains
    if stats["queried"] > 0 and stats["ok"] == 0 and stats["not_found"] == 0 and stats["error"] == stats["queried"]:
        eprint("[!] All Shodan queries failed — check API key and network.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
