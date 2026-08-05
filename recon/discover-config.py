#!/usr/bin/env python3
# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
"""Discover operator config under ~/.discover (API keys, name, view timezone).

Used by host-scan-statusd /config endpoints. CLI JSON never prints secret
values (presence only). statusd loads get_all() / write helpers in-process for
localhost Audit Config so keys can be edited without clear-text logging sinks.

  python3 recon/discover-config.py get-all --json
  python3 recon/discover-config.py set-api-keys --json --body '{"NVD_API_KEY":"..."}'
  python3 recon/discover-config.py set-operator-name --name Carter --report /path/to/report --json
  python3 recon/discover-config.py set-timezone --tz America/Chicago --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

API_KEY_NAMES = ("NVD_API_KEY", "SHODAN_API_KEY", "WPSCAN_API_TOKEN")

# Display-only timezone IDs (UTC write is mandatory; see AGENTS.md).
US_VIEW_TIMEZONES = (
    ("UTC", "UTC"),
    ("America/New_York", "Eastern (US)"),
    ("America/Chicago", "Central (US)"),
    ("America/Denver", "Mountain (US)"),
    ("America/Phoenix", "Arizona (US)"),
    ("America/Los_Angeles", "Pacific (US)"),
)

VALID_TZ_IDS = {tid for tid, _ in US_VIEW_TIMEZONES}


def discover_home() -> Path:
    return Path.home() / ".discover"


def api_keys_path() -> Path:
    return discover_home() / "api-keys"


def operator_name_path() -> Path:
    return discover_home() / "operator-name"


def timezone_path() -> Path:
    return discover_home() / "timezone"


def ensure_discover_dir() -> None:
    d = discover_home()
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass


def read_api_keys() -> dict[str, str]:
    """KEY -> value (empty string if unset). File values only (not env)."""
    out = {k: "" for k in API_KEY_NAMES}
    path = api_keys_path()
    if not path.is_file():
        return out
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key in out:
            out[key] = val
    return out


def write_api_keys(updates: dict[str, str]) -> dict[str, str]:
    """Merge updates into api-keys file. Empty string clears a key (commented)."""
    ensure_discover_dir()
    path = api_keys_path()
    current = read_api_keys()
    for k in API_KEY_NAMES:
        if k in updates:
            current[k] = str(updates[k] if updates[k] is not None else "").strip()

    lines = [
        "# Discover API keys — managed by Audit Config (and Update seed).",
        "# chmod 600; do not commit this file.",
        "#",
        "# NVD: https://nvd.nist.gov/developers/request-an-api-key",
        "# Shodan: https://account.shodan.io",
        "# WPScan: https://wpscan.com/api",
        "#",
    ]
    for k in API_KEY_NAMES:
        v = current.get(k) or ""
        if v:
            lines.append(f"{k}={v}")
        else:
            lines.append(f"# {k}=")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return current


def operator_name_valid(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z]{1,10}", name or ""))


def operator_name_canonical(name: str) -> str:
    name = (name or "").strip()
    if not name:
        return ""
    return name[0].upper() + name[1:].lower()


def read_operator_name() -> str:
    path = operator_name_path()
    if not path.is_file():
        return ""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
        name = (raw[0] if raw else "").strip()
    except OSError:
        return ""
    if not operator_name_valid(name):
        return ""
    return operator_name_canonical(name)


def write_operator_name(name: str) -> str:
    if not operator_name_valid(name):
        raise ValueError(
            "Operator name must be 1–10 letters only (no spaces or numbers)."
        )
    ensure_discover_dir()
    canon = operator_name_canonical(name)
    path = operator_name_path()
    path.write_text(canon + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return canon


def rewrite_audit_operator_name(report_root: Path, old_name: str, new_name: str) -> int:
    """Replace only the operator field for old_name → new_name in audit log.

    Multi-operator logs: lines for other names (Paul, Samuel, …) are left unchanged.
    Does not rewrite names inside Action text (e.g. Imported operator package (Bob: …)).
    """
    log = report_root / "tools" / "audit" / "log.txt"
    if not log.is_file():
        return 0
    old_c = operator_name_canonical(old_name) if operator_name_valid(old_name) else ""
    new_c = operator_name_canonical(new_name)
    if not old_c or not new_c or old_c.casefold() == new_c.casefold():
        return 0

    # Operator is field 2: time | Name | IP | action  (or legacy 3-field time | IP | action — skip)
    # Current: mm-dd-yyyy - hh:mm Z | Name | …
    pat = re.compile(
        r"^(\d{2}-\d{2}-\d{4}\s+-\s+\d{2}:\d{2}\s+Z\s+\|\s+)"
        + r"("
        + re.escape(old_c)
        + r")"
        + r"(\s+\|)",
        re.IGNORECASE,
    )
    # Legacy: mm-dd-yyyy Z - hh:mm | Name | …
    pat_legacy = re.compile(
        r"^(\d{2}-\d{2}-\d{4}\s+Z\s+-\s+\d{2}:\d{2}\s+\|\s+)"
        + r"("
        + re.escape(old_c)
        + r")"
        + r"(\s+\|)",
        re.IGNORECASE,
    )

    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0

    changed = 0
    out_lines: list[str] = []
    for line in text.splitlines(keepends=True):
        raw = line.rstrip("\n\r")
        ending = line[len(raw) :]
        new_line = raw
        m = pat.match(raw) or pat_legacy.match(raw)
        if m:
            # Only the matched operator token (group 2) is replaced.
            new_line = m.group(1) + new_c + m.group(3) + raw[m.end() :]
            if new_line != raw:
                changed += 1
        out_lines.append(new_line + ending)

    if changed:
        log.write_text("".join(out_lines), encoding="utf-8")
    return changed


def read_timezone() -> str:
    path = timezone_path()
    if not path.is_file():
        return "UTC"
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
        tid = (raw[0] if raw else "").strip()
    except OSError:
        return "UTC"
    if tid not in VALID_TZ_IDS:
        return "UTC"
    return tid


def write_timezone(tz_id: str) -> str:
    tid = (tz_id or "").strip()
    if tid not in VALID_TZ_IDS:
        raise ValueError(
            "Timezone must be UTC or a supported US zone "
            f"({', '.join(sorted(VALID_TZ_IDS))})."
        )
    ensure_discover_dir()
    path = timezone_path()
    path.write_text(tid + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return tid


def get_all() -> dict:
    """Full config including API key values (in-process use only — statusd Config).

    Do not print this dict to logs/stdout. CLI uses get_all_public() instead.
    """
    keys = read_api_keys()
    return {
        "ok": True,
        "api_keys": keys,
        "operator_name": read_operator_name(),
        "timezone": read_timezone(),
        "timezones": [{"id": tid, "label": lab} for tid, lab in US_VIEW_TIMEZONES],
        "paths": {
            "api_keys": str(api_keys_path()),
            "operator_name": str(operator_name_path()),
            "timezone": str(timezone_path()),
        },
    }


def get_all_public() -> dict:
    """CLI status without reading or printing API key material.

    Does not open ~/.discover/api-keys. statusd Config uses get_all() in-process
    for full key values (never printed by this CLI).
    """
    return {
        "ok": True,
        "operator_name": read_operator_name(),
        "timezone": read_timezone(),
        "timezones": [{"id": tid, "label": lab} for tid, lab in US_VIEW_TIMEZONES],
        "paths": {
            "config_file": str(api_keys_path()),
            "operator_name": str(operator_name_path()),
            "timezone": str(timezone_path()),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Discover operator config")
    parser.add_argument(
        "action",
        choices=("get-all", "set-api-keys", "set-operator-name", "set-timezone"),
    )
    parser.add_argument("--json", action="store_true", help="JSON stdout")
    parser.add_argument("--name", default="", help="Operator name for set-operator-name")
    parser.add_argument(
        "--report",
        default="",
        help="Engagement report root (rewrite audit log on name change)",
    )
    parser.add_argument("--tz", default="", help="Timezone id for set-timezone")
    parser.add_argument(
        "--body",
        default="",
        help="JSON body for set-api-keys (or pass via stdin with --json stdin)",
    )
    args = parser.parse_args(argv)

    def emit_ok_json(text: str, code: int = 0) -> int:
        """Print a fixed JSON string (no secret dataflow into dumps)."""
        print(text)
        return code

    def emit_err_code(code_id: str, code: int = 2) -> int:
        """Print a fixed error by id only (no dynamic secret-related strings).

        CodeQL flags printing names like NVD_API_KEY / TOKEN as clear-text
        sensitive data; keep messages bland and constant.
        """
        messages = {
            "body_required": "JSON body with key fields required",
            "invalid_json": "invalid JSON body",
            "object_required": "JSON object required",
            "no_fields": "Provide at least one key field to update",
            "name_required": "name is required",
            "name_invalid": "Operator name must be 1-10 letters only.",
            "tz_invalid": "Timezone must be UTC or a supported US zone.",
            "failed": "config operation failed",
            "unknown": "unknown action",
        }
        message = messages.get(code_id, messages["failed"])
        if args.json:
            # Fixed shape; message is always from the map above.
            print('{"ok":false,"error":"' + message.replace('"', "") + '"}')
        else:
            print(message, file=sys.stderr)
        return code

    try:
        if args.action == "get-all":
            # Build only non-secret fields; never open the api-keys file here.
            payload = get_all_public()
            if args.json:
                return emit_ok_json(json.dumps(payload, ensure_ascii=False), 0)
            return emit_ok_json(json.dumps(payload, indent=2, ensure_ascii=False), 0)

        if args.action == "set-api-keys":
            raw = args.body.strip()
            if not raw and not sys.stdin.isatty():
                raw = sys.stdin.read().strip()
            if not raw:
                return emit_err_code("body_required", 2)
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                return emit_err_code("invalid_json", 2)
            if not isinstance(body, dict):
                return emit_err_code("object_required", 2)
            updates = {}
            for k in API_KEY_NAMES:
                if k in body:
                    # Values go only to write_api_keys — never to print/logging.
                    updates[k] = str(body.get(k) or "")
                aliases = {
                    "NVD_API_KEY": ("nvd", "nvd_api_key"),
                    "SHODAN_API_KEY": ("shodan", "shodan_api_key"),
                    "WPSCAN_API_TOKEN": ("wpscan", "wpscan_api_token"),
                }
                for a in aliases.get(k, ()):
                    if a in body and k not in updates:
                        updates[k] = str(body.get(a) or "")
            if not updates:
                return emit_err_code("no_fields", 2)
            write_api_keys(updates)
            # Literal success only — no dumps of body/updates.
            return emit_ok_json('{"ok":true,"saved":true}', 0)

        if args.action == "set-operator-name":
            name = (args.name or "").strip()
            if not name:
                return emit_err_code("name_required", 2)
            old = read_operator_name()
            try:
                new = write_operator_name(name)
            except ValueError:
                return emit_err_code("name_invalid", 2)
            rewritten = 0
            report = (args.report or "").strip()
            if report and old and old != new:
                rewritten = rewrite_audit_operator_name(Path(report), old, new)
                # Rebuild Audit page when possible
                discover = Path(__file__).resolve().parent.parent
                builder = discover / "recon" / "audit-build.py"
                template = discover / "report" / "pages" / "audit.htm"
                if builder.is_file() and Path(report).is_dir():
                    import subprocess

                    subprocess.run(
                        [
                            sys.executable,
                            str(builder),
                            str(Path(report).resolve()),
                            str(template) if template.is_file() else "",
                        ],
                        capture_output=True,
                        timeout=120,
                        check=False,
                    )
            payload = {
                "ok": True,
                "operator_name": new,
                "previous": old,
                "audit_lines_rewritten": rewritten,
            }
            if args.json:
                return emit_ok_json(json.dumps(payload, ensure_ascii=False), 0)
            return emit_ok_json(json.dumps(payload, indent=2, ensure_ascii=False), 0)

        if args.action == "set-timezone":
            try:
                tid = write_timezone(args.tz)
            except ValueError:
                return emit_err_code("tz_invalid", 2)
            payload = {"ok": True, "timezone": tid}
            if args.json:
                return emit_ok_json(json.dumps(payload, ensure_ascii=False), 0)
            return emit_ok_json(json.dumps(payload, indent=2, ensure_ascii=False), 0)

    except Exception:
        return emit_err_code("failed", 1)

    return emit_err_code("unknown", 2)


if __name__ == "__main__":
    raise SystemExit(main())
