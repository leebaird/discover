# /// script
# dependencies = [
#   "gspread",
#   "google-auth-oauthlib",
#   "google-auth-httplib2",
#   "tzdata",
# ]
# ///

"""Google Sheet helper for Discover host scans.

Authorize from Audit Config (browser OAuth). Append during a scan never
opens a browser: missing or invalid tokens skip the row.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import gspread
import zoneinfo
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]


def token_path() -> Path:
    return Path.home() / ".discover" / "google-token.json"


def creds_path() -> Path:
    return Path.home() / ".discover" / "client_secret.json"


def write_secret_file(path: Path, text: str) -> None:
    """Create or replace a file at mode 0600 (including an existing world-readable file)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def tighten_mode(path: Path) -> None:
    if path.is_file():
        try:
            path.chmod(0o600)
        except OSError:
            pass


def get_credentials(*, interactive: bool) -> Credentials:
    client_secret_file = creds_path()
    saved = token_path()

    if not client_secret_file.is_file():
        print("Error: ~/.discover/client_secret.json not found.", file=sys.stderr)
        sys.exit(1)

    tighten_mode(client_secret_file)

    creds = None
    if saved.is_file():
        try:
            creds = Credentials.from_authorized_user_file(str(saved), SCOPES)
        except Exception:
            print("Warning: Failed to load existing token.", file=sys.stderr)
            creds = None

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception:
                print("Error refreshing token.", file=sys.stderr)
                creds = None

        if not creds:
            if not interactive:
                print(
                    "Google Sheet: not authorized. Use Audit Config → Google Sheet → Authorize.",
                    file=sys.stderr,
                )
                sys.exit(2)

            flow = InstalledAppFlow.from_client_secrets_file(
                str(client_secret_file), SCOPES
            )
            creds = flow.run_local_server(port=0)

        write_secret_file(saved, creds.to_json())

    return creds


def cmd_authorize() -> int:
    get_credentials(interactive=True)
    print("Google Sheet authorization saved.")
    return 0


def cmd_append(args: argparse.Namespace) -> int:
    creds = get_credentials(interactive=False)
    client = gspread.authorize(creds)
    sh = client.open_by_url(args.sheets_url)
    metadata = sh.fetch_sheet_metadata()

    dt_utc = datetime.strptime(args.timestamp, "%m/%d/%Y - %H:%M Z").replace(
        tzinfo=timezone.utc
    )
    tz_name = (metadata.get("properties") or {}).get("timeZone") or "UTC"
    sheet_tz = zoneinfo.ZoneInfo(tz_name)
    date_str = dt_utc.astimezone(sheet_tz).strftime("%m/%d/%Y %H:%M:%S")

    target_raw = args.target or ""
    if target_raw.startswith(("http://", "https://")):
        target_hostname = (urlparse(target_raw).hostname or "").lower()
    else:
        target_hostname = target_raw.strip()

    # Col A: Date (sheet timezone), B: Operator, C: IP, D: Target, E: Command
    worksheet = sh.get_worksheet(0)
    worksheet.append_row(
        [date_str, args.operator, args.ip, target_hostname, args.command]
    )
    return 0


def cmd_status() -> int:
    payload = {
        "ok": True,
        "has_client_secret": creds_path().is_file(),
        "has_token": token_path().is_file(),
        "client_secret_path": str(creds_path()),
        "token_path": str(token_path()),
    }
    print(json.dumps(payload))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Discover Google Sheet host-scan log")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("authorize", help="Browser OAuth; write ~/.discover/google-token.json")
    sub.add_parser("status", help="JSON presence of client_secret and token")

    ap = sub.add_parser("append", help="Append one host-scan row (no browser)")
    ap.add_argument("sheets_url")
    ap.add_argument("timestamp")
    ap.add_argument("operator")
    ap.add_argument("ip")
    ap.add_argument("target")
    ap.add_argument("command")

    args = parser.parse_args(argv)

    try:
        if args.cmd == "authorize":
            return cmd_authorize()
        if args.cmd == "status":
            return cmd_status()
        if args.cmd == "append":
            return cmd_append(args)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"Error syncing to Google Sheet: {exc}", file=sys.stderr)
        return 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
