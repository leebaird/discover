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
opens a browser. A configured sheet that cannot be written stops the scan.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import sys
from contextlib import contextmanager
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


def plain_text_target(worksheet: gspread.Worksheet, a1: str) -> None:
    """Keep a hostname as text. Sheets otherwise links anything ending in .com."""
    worksheet.format(
        a1,
        {
            "numberFormat": {"type": "TEXT"},
            "hyperlinkDisplayType": "PLAIN_TEXT",
            "textFormat": {},
        },
    )


# Hundredths of a pixel for ASCII 32..126. Liberation Sans at 13px matches
# Arial 10pt, which is the spreadsheet default. Used only to count wraps.
_ACTION_CHAR_WIDTHS = (
    361, 361, 461, 723, 723, 1156, 867, 248, 433, 433, 506, 759, 361, 433, 361, 361,
    723, 723, 723, 723, 723, 723, 723, 723, 723, 723, 361, 361, 759, 759, 759, 723,
    1320, 867, 867, 939, 939, 867, 794, 1011, 939, 361, 650, 867, 723, 1083, 939, 1011,
    867, 1011, 939, 867, 794, 939, 867, 1227, 867, 867, 794, 361, 361, 361, 609, 723,
    433, 723, 723, 650, 723, 723, 361, 723, 723, 289, 289, 650, 289, 1083, 723, 723,
    723, 723, 433, 650, 361, 723, 650, 939, 650, 650, 650, 434, 338, 434, 759,
)


def _char_width(ch: str) -> int:
    code = ord(ch)
    if 32 <= code <= 126:
        return _ACTION_CHAR_WIDTHS[code - 32]
    return 1083


# Liberation Mono 13px is 7.8px per glyph. That matches Courier New 10pt,
# which is what an nmap PORT table uses in column F.
_COURIER_CHAR_WIDTH = 780


def _courier_width(_ch: str) -> int:
    return _COURIER_CHAR_WIDTH


def action_line_count(
    text: str,
    column_px: int,
    pad_px: int = 6,
    width_of=_char_width,
) -> int:
    """Wrapped lines a cell will show. Hard newlines count, and so does wrap."""
    usable = max(width_of("M"), (column_px - pad_px) * 100)
    total = 0
    for para in (text or "").split("\n"):
        if para == "":
            total += 1
            continue
        count = 0
        current = ""
        current_w = 0
        for word in para.split(" "):
            word_w = sum(width_of(ch) for ch in word)
            space_w = width_of(" ") if current else 0
            if current and current_w + space_w + word_w <= usable:
                current = current + " " + word
                current_w += space_w + word_w
                continue
            if current:
                count += 1
                current = ""
                current_w = 0
            if word_w <= usable:
                current = word
                current_w = word_w
                continue
            chunk = ""
            chunk_w = 0
            for ch in word:
                cw = width_of(ch)
                if chunk and chunk_w + cw > usable:
                    count += 1
                    chunk = ch
                    chunk_w = cw
                else:
                    chunk += ch
                    chunk_w += cw
            current = chunk
            current_w = chunk_w
        if current:
            count += 1
        total += max(count, 1)
    return max(total, 1)


def action_row_pixels(lines: int) -> int:
    """Row height when Action wraps. One line keeps the default row."""
    if lines <= 1:
        return 0
    # Default row is 20px for one line of Arial 10. Each further line is 18px,
    # plus a few pixels so the last line is not clipped.
    return 20 + (lines - 1) * 18 + 4


def column_pixel_width(worksheet: gspread.Worksheet, column: str) -> int:
    title = "'" + worksheet.title.replace("'", "''") + "'"
    meta = worksheet.spreadsheet.fetch_sheet_metadata(params={
        "includeGridData": "true",
        "ranges": [f"{title}!{column}1"],
        "fields": "sheets.data.columnMetadata.pixelSize",
    })
    cols = meta["sheets"][0]["data"][0].get("columnMetadata") or [{}]
    return int(cols[0].get("pixelSize") or 100)


def action_column_width(worksheet: gspread.Worksheet) -> int:
    return column_pixel_width(worksheet, "E")


def next_log_row(column_a: list) -> int:
    """1-based row under the last date. Does not reuse that row."""
    last = 0
    for index, value in enumerate(column_a, start=1):
        if value is not None and str(value).strip():
            last = index
    return last + 1


@contextmanager
def sheet_write_lock():
    """One local scan writes the sheet at a time, so two starts cannot pick the same row."""
    path = Path.home() / ".discover" / "op-notes.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def top_align_log_row(worksheet: gspread.Worksheet, row: int) -> None:
    """Date, operator, IP, target, command, and result sit at the top of the row."""
    worksheet.format(f"A{row}:F{row}", {"verticalAlignment": "TOP"})


def write_new_log_row(worksheet: gspread.Worksheet, values: list[str]) -> int:
    """Write under the last filled date. Never replace that row."""
    row = next_log_row(worksheet.col_values(1))
    occupied = worksheet.acell(f"A{row}").value
    if occupied:
        at_bottom = row > worksheet.row_count
        worksheet.insert_row(
            values,
            index=row,
            value_input_option="RAW",
            inherit_from_before=at_bottom,
        )
        return row
    worksheet.update(
        [values],
        f"A{row}:F{row}",
        value_input_option="RAW",
    )
    return row


def set_row_heights(worksheet: gspread.Worksheet, heights: dict[int, int]) -> None:
    """Set 1-based row heights in pixels."""
    if not heights:
        return
    worksheet.spreadsheet.batch_update({
        "requests": [
            {
                "updateDimensionProperties": {
                    "range": {
                        "sheetId": worksheet.id,
                        "dimension": "ROWS",
                        "startIndex": row - 1,
                        "endIndex": row,
                    },
                    "properties": {"pixelSize": pixels},
                    "fields": "pixelSize",
                }
            }
            for row, pixels in heights.items()
        ]
    })


def expand_action_rows(worksheet: gspread.Worksheet, heights: dict[int, int]) -> None:
    """Grow rows whose Action cell wraps past one line. heights: 1-based row to pixels."""
    if not heights:
        return
    worksheet.format(
        [f"E{row}" for row in heights],
        {"wrapStrategy": "WRAP", "verticalAlignment": "TOP"},
    )
    set_row_heights(worksheet, heights)


def log_row_height(
    command: str,
    result: str,
    *,
    action_px: int,
    result_px: int,
    pad_px: int,
) -> tuple[int, int]:
    """Pixels for the row, and whether column E itself needs wrap.

    The row uses the taller of a wrapped command and a multi-line nmap table.
    One line in both columns keeps the sheet's default row height (returns 0).
    """
    action_lines = action_line_count(command or "", action_px, pad_px) if command else 1
    result_lines = 1
    if (result or "").lstrip().startswith("PORT"):
        result_lines = action_line_count(
            result,
            result_px,
            pad_px,
            width_of=_courier_width,
        )
    pixels = max(action_row_pixels(action_lines), action_row_pixels(result_lines))
    return pixels, action_row_pixels(action_lines)


def cmd_authorize() -> int:
    get_credentials(interactive=True)
    print("Google Sheet authorization saved.")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Open the sheet without appending a row."""
    creds = get_credentials(interactive=False)
    client = gspread.authorize(creds)
    client.open_by_url(args.sheets_url)
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
    date_str = dt_utc.astimezone(sheet_tz).strftime("%m/%d/%Y - %H:%M")

    target_raw = args.target or ""
    if target_raw.startswith(("http://", "https://")):
        target_hostname = (urlparse(target_raw).hostname or "").lower()
    else:
        target_hostname = target_raw.strip()

    # Col A: Date (sheet timezone), B: Operator, C: IP, D: Target, E: Command, F: Result.
    # Write the next empty row. append_row follows Sheets' table detector and
    # was replacing the last scan.
    worksheet = sh.get_worksheet(0)
    result_text = args.result or ""
    with sheet_write_lock():
        row_num = write_new_log_row(
            worksheet,
            [
                date_str,
                args.operator,
                args.ip,
                target_hostname,
                args.command,
                result_text,
            ],
        )
    row = str(row_num)
    if row and target_hostname:
        try:
            plain_text_target(worksheet, f"D{row}")
        except Exception:
            pass
    if result_text.lstrip().startswith("PORT"):
        try:
            worksheet.format(
                f"F{row}",
                {
                    "wrapStrategy": "WRAP",
                    "verticalAlignment": "TOP",
                    "textFormat": {"fontFamily": "Courier New"},
                },
            )
        except Exception:
            pass
    if row and (args.command or result_text.lstrip().startswith("PORT")):
        try:
            padding = ((metadata.get("properties") or {}).get("defaultFormat") or {}).get("padding") or {}
            pad = int(padding.get("left") or 0) + int(padding.get("right") or 0)
            if pad <= 0:
                pad = 6
            pixels, action_pixels = log_row_height(
                args.command or "",
                result_text,
                action_px=column_pixel_width(worksheet, "E"),
                result_px=column_pixel_width(worksheet, "F"),
                pad_px=pad,
            )
            if action_pixels:
                worksheet.format(
                    f"E{row}",
                    {"wrapStrategy": "WRAP", "verticalAlignment": "TOP"},
                )
            if pixels:
                set_row_heights(worksheet, {int(row): pixels})
        except Exception:
            pass
    try:
        top_align_log_row(worksheet, int(row))
    except Exception:
        pass
    # Host-scan captures this and does not show it. It is the row to update later.
    print(f"DISCOVER_ROW {row}")
    return 0


def cmd_set_result(args: argparse.Namespace) -> int:
    """Write column F on a row this scan already appended. Do not add a row."""
    row_text = str(args.row).strip()
    if not row_text.isdigit() or int(row_text) < 2:
        print("Error syncing to Google Sheet: bad row.", file=sys.stderr)
        return 1
    row = int(row_text)
    creds = get_credentials(interactive=False)
    client = gspread.authorize(creds)
    sh = client.open_by_url(args.sheets_url)
    worksheet = sh.get_worksheet(0)
    result = args.result or ""
    with sheet_write_lock():
        occupied = worksheet.acell(f"A{row}").value
        if not occupied or not str(occupied).strip():
            print("Error syncing to Google Sheet: row has no date.", file=sys.stderr)
            return 1
        worksheet.update([[result]], f"F{row}", value_input_option="RAW")
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

    ck = sub.add_parser("check", help="Open the sheet without appending a row")
    ck.add_argument("sheets_url")

    ap = sub.add_parser("append", help="Append one host-scan row (no browser)")
    ap.add_argument("sheets_url")
    ap.add_argument("timestamp")
    ap.add_argument("operator")
    ap.add_argument("ip")
    ap.add_argument("target")
    ap.add_argument("command")
    ap.add_argument("result", nargs="?", default="")

    sr = sub.add_parser("set-result", help="Write column F on an existing scan row")
    sr.add_argument("sheets_url")
    sr.add_argument("row")
    sr.add_argument("result", nargs="?", default="")

    args = parser.parse_args(argv)

    try:
        if args.cmd == "authorize":
            return cmd_authorize()
        if args.cmd == "status":
            return cmd_status()
        if args.cmd == "check":
            return cmd_check(args)
        if args.cmd == "append":
            return cmd_append(args)
        if args.cmd == "set-result":
            return cmd_set_result(args)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"Error syncing to Google Sheet: {exc}", file=sys.stderr)
        return 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
