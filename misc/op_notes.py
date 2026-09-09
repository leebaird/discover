# /// script
# dependencies = [
#   "gspread",
#   "google-auth-oauthlib",
#   "google-auth-httplib2",
#   "tzdata",
# ]
# ///

import sys
import os
from pathlib import Path
from urllib.parse import urlparse
import gspread
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from datetime import datetime, timezone
import zoneinfo

# Scopes for Google Sheets API
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

def get_credentials():
    token_path = Path.home() / ".discover" / "google-token.json"
    creds_path = Path.home() / ".discover" / "client_secret.json"

    if not creds_path.exists():
        print(f"Error: {creds_path} not found.", file=sys.stderr)
        sys.exit(1)

    creds = None
    if token_path.exists():
        try:
            creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
        except Exception as e:
            print(f"Warning: Failed to load existing token: {e}", file=sys.stderr)
            creds = None

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                print(f"Error refreshing token: {e}", file=sys.stderr)
                creds = None

        if not creds:
            flow = InstalledAppFlow.from_client_secrets_file(str(creds_path), SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for the next run
        token_path.parent.mkdir(parents=True, exist_ok=True)

        original_umask = os.umask(0)
        try:
            # Open low-level file descriptor with the exact mode we want
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(token_path, flags, mode=0o600)

            with os.fdopen(fd, "w") as f:
                f.write(creds.to_json())
        finally:
            os.umask(original_umask)

    return creds

def main():
    if len(sys.argv) < 7:
        print(f"Usage: {sys.argv[0]} <sheets_url> <timestamp> <operator> <ip> <target> <command>", file=sys.stderr)
        sys.exit(1)

    sheets_url = sys.argv[1]
    timestamp_str = sys.argv[2]
    operator = sys.argv[3]
    ip = sys.argv[4]
    target_raw = sys.argv[5]
    command = sys.argv[6]

    try:
        creds = get_credentials()
        client = gspread.authorize(creds)

        sh = client.open_by_url(sheets_url)
        metadata = sh.fetch_sheet_metadata()

        # This format must be the same as in run-host-scan.sh
        dt_utc = datetime.strptime(timestamp_str, "%m/%d/%Y - %H:%M Z").replace(tzinfo=timezone.utc)

        # Convert to the spreadsheet's "native" time zone in File | Settings
        sh_tz = zoneinfo.ZoneInfo(metadata['properties']['timeZone'])
        dt_sh = dt_utc.astimezone(sh_tz)
        date_sh_str = dt_sh.strftime("%m/%d/%Y %H:%M:%S")

        # Derive target hostname
        target_hostname = ""
        if target_raw.startswith(("http://", "https://")):
            parsed = urlparse(target_raw)
            target_hostname = (parsed.hostname or "").lower()
        else:
            # Fallback for non-URL targets
            target_hostname = target_raw.strip()


        # Col A: Date (ET), B: Operator, C: IP, D: Target (Host), E: Command
        worksheet = sh.get_worksheet(0)
        worksheet.append_row([date_sh_str, operator, ip, target_hostname, command])

    except Exception as e:
        print(f"Error syncing to Google Sheet: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
