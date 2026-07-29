#!/usr/bin/env python3
"""Stamp the engagement homepage date (index.htm) to today.

Discover reports show a single date under the home hero (#DATE# after passive,
then a plain <span class="value">Month DD, YYYY</span>). Call this whenever
the report is meaningfully updated: import, Active, host-scan, Shodan, CVE
refresh, operator package merge, etc.

Usage:
  python3 recon/touch-report-date.py <report_dir>
"""

from __future__ import annotations

import re
import sys
from datetime import datetime
from pathlib import Path


def report_date_stamp() -> str:
    """Match Discover DATESTAMP: date +\"%B %d, %Y\" (zero-padded day)."""
    return datetime.now().strftime("%B %d, %Y")


def touch_report_index_date(report_dir: str | Path) -> bool:
    """Update index.htm homepage date to today. Returns True if written."""
    path = Path(report_dir).expanduser().resolve() / "index.htm"
    if not path.is_file():
        return False

    text = path.read_text(encoding="utf-8", errors="replace")
    stamp = report_date_stamp()
    original = text

    if "#DATE#" in text:
        text = text.replace("#DATE#", stamp)
    else:
        # Live reports: first meta item is bare date, then Company, then Domain.
        text2, n = re.subn(
            r'(<div class="inc-home-meta-item">\s*'
            r'<span class="value">)([^<]*)(</span>\s*</div>\s*'
            r'<div class="inc-home-meta-item">\s*'
            r'<span class="inc-home-meta-label">Company</span>)',
            rf"\g<1>{stamp}\g<3>",
            text,
            count=1,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if n:
            text = text2
        else:
            # Fallback: first home-meta bare value only
            text2, n = re.subn(
                r'(class="inc-home-meta-item">\s*<span class="value">)([^<]*)(</span>)',
                rf"\g<1>{stamp}\g<3>",
                text,
                count=1,
                flags=re.IGNORECASE | re.DOTALL,
            )
            if n:
                text = text2

    if text == original:
        return False
    path.write_text(text, encoding="utf-8")
    return True


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("Usage: touch-report-date.py <report_dir>", file=sys.stderr)
        return 2
    ok = touch_report_index_date(argv[1])
    if ok:
        print(f"[*] Report date → {report_date_stamp()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
